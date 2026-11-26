package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/csms"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/kps"
)

// TestInventory: the inventory lists what the services hold, with the
// account IAM says owns each project.
func TestInventory(t *testing.T) {
	t.Parallel()
	inst := startInstance(t, nil)
	info := inst.services(t)
	if status, body := inst.send(t, http.MethodPost, "/vpc/v1/"+info.ProjectID+"/vpcs",
		[]byte(`{"vpc": {"name": "inventoried", "cidr": "10.0.0.0/16"}}`)); status != http.StatusOK {
		t.Fatalf("creating a VPC = %d %s", status, body)
	}

	status, body := inst.get(t, "/_weistack/inventory?type=vpc.vpcs")
	if status != http.StatusOK {
		t.Fatalf("GET inventory = %d %s", status, body)
	}
	var out struct {
		Resources []struct {
			Name      string `json:"name"`
			AccountID string `json:"account_id"`
			ProjectID string `json:"project_id"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Resources) != 1 || out.Resources[0].Name != "inventoried" ||
		out.Resources[0].AccountID != info.AccountID || info.AccountID == "" || out.Resources[0].ProjectID != info.ProjectID {
		t.Fatalf("inventory = %s; want the VPC, in account %s", body, info.AccountID)
	}
}

// TestInventoryThroughAdminCommand: under enforce, weistack admin signs
// the query string too.
func TestInventoryThroughAdminCommand(t *testing.T) {
	t.Parallel()
	vars := map[string]string{"WEISTACK_IAM": "enforce", "WEISTACK_TLS_DIR": t.TempDir()}
	inst := startInstance(t, vars)
	_, port, _ := net.SplitHostPort(inst.addr)
	if status, _ := inst.get(t, "/_weistack/inventory"); status != http.StatusUnauthorized {
		t.Fatalf("unsigned GET inventory = %d, want 401", status)
	}
	var stdout bytes.Buffer
	err := Run(context.Background(), Env{
		Args:   []string{"admin", "GET", "inventory?type=vpc.vpcs&region_id=ap-southeast-1", "-port", port},
		Getenv: func(k string) string { return vars[k] }, Stdout: &stdout, Stderr: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("admin GET inventory: %v", err)
	}
	if got := stdout.String(); !bytes.Contains([]byte(got), []byte(`"count":0`)) {
		t.Fatalf("admin GET inventory = %s, want an empty inventory", got)
	}
}

// TestEveryServiceReports verifies that every stateful service reports its
// resources to the inventory, hosted services are wired under their host, and
// stateless services hold no store scopes.
func TestEveryServiceReports(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acct, err := identity.NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	adm, err := identity.NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	vlt, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Region: "ap-southeast-1", SeedDir: t.TempDir()}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	services, hosted, err := buildServices(t.Context(), cfg, "0123456789abcdef0123456789abcdef", t.TempDir(), st, nil,
		lifecycle.New(lifecycle.Options{Logger: log}), ids.New(), log, identity.NewDirectory(acct, adm), vlt)
	if err != nil {
		t.Fatal(err)
	}

	mounted := make(map[string]server.Service, len(services))
	var reporters []inventory.Reporter
	for _, svc := range services {
		mounted[svc.Name()] = svc
		rep, ok := svc.(inventory.Reporter)
		switch svc.Name() {
		case "sts", "eps":
			if ok {
				t.Errorf("service %q implements inventory.Reporter; stateless service must not report", svc.Name())
			}
		default:
			if !ok {
				t.Errorf("service %q does not implement inventory.Reporter", svc.Name())
			} else {
				reporters = append(reporters, rep)
			}
		}
	}

	for host, reps := range hosted {
		if mounted[host] == nil {
			t.Errorf("hosted[%q] names unknown service", host)
		}
		if len(reps) == 0 {
			t.Errorf("hosted[%q] is empty", host)
		}
		for i, rep := range reps {
			if rep == nil {
				t.Errorf("hosted[%q][%d] is nil", host, i)
				continue
			}
			reporters = append(reporters, rep)
		}
	}

	var hasEIP, hasKPS, hasCSMS bool
	for _, rep := range hosted["vpc"] {
		if _, ok := rep.(*eip.Service); ok {
			hasEIP = true
		}
	}
	if !hasEIP {
		t.Errorf("hosted[%q] = %v; want *eip.Service", "vpc", hosted["vpc"])
	}
	for _, rep := range hosted["kms"] {
		if _, ok := rep.(*kps.Service); ok {
			hasKPS = true
		}
		if _, ok := rep.(*csms.Service); ok {
			hasCSMS = true
		}
	}
	if !hasKPS {
		t.Errorf("hosted[%q] = %v; want *kps.Service", "kms", hosted["kms"])
	}
	if !hasCSMS {
		t.Errorf("hosted[%q] = %v; want *csms.Service", "kms", hosted["kms"])
	}

	dump, err := st.Dump(t.Context())
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	for raw := range dump {
		sc, err := store.ParseScope(raw)
		if err != nil {
			t.Fatalf("ParseScope(%q): %v", raw, err)
		}
		if strings.HasPrefix(sc.Kind, "sts.") || strings.HasPrefix(sc.Kind, "eps.") {
			t.Errorf("stateless service holds store scope %q", raw)
		}
	}

	if _, err := inventory.New(inventory.Options{Reporters: reporters}).Collect(t.Context()); err != nil {
		t.Fatalf("Collect across all services: %v", err)
	}
}
