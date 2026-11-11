package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	testProject  = "0123456789abcdef0123456789abcdef"
	otherProject = "ffffffffffffffffffffffffffffffff"
	testRegion   = "ap-southeast-1"
	testHost     = "rds." + testRegion + ".myhuaweicloud.com"
	testDelay    = 2 * time.Second
	unknownUUID  = "00000000-0000-4000-8000-000000000000"
)

var (
	testTenant = Tenant{Region: testRegion, ProjectID: testProject}
	testEpoch  = time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
)

type env struct {
	svc     *Service
	network *vpc.Service
	store   store.Store
	engine  *lifecycle.Engine
	clock   *lifecycle.FakeClock
	handler http.Handler
	net     netIDs
}

// netIDs is the VPC, subnet and security group instances are created in.
type netIDs struct{ vpc, subnet, group string }

type options struct {
	store  store.Store
	quota  int
	faults lifecycle.FaultInjector
	// reuse is the network of a previous run on the same store; when set,
	// no new network is created.
	reuse *netIDs
}

func newEnv(t *testing.T) *env { return newEnvWith(t, options{}) }

func newEnvWith(t *testing.T, o options) *env {
	t.Helper()
	if o.store == nil {
		o.store = store.NewMemory()
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log, Faults: o.faults})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; _ = o.store.Close() })

	gen := ids.NewSeeded(19)
	network, err := vpc.New(vpc.Deps{Store: o.store, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Deps{Store: o.store, Engine: engine, IDs: gen, Logger: log, Network: network, MaxInstances: o.quota, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Options{
		Config: cfg, ProjectID: testProject, Logger: log, Store: o.store, Engine: engine, IDs: gen,
		Services: []server.Service{svc},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{svc: svc, network: network, store: o.store, engine: engine, clock: clock, handler: srv.Handler()}
	if o.reuse != nil {
		e.net = *o.reuse
	} else {
		e.net = e.makeNetwork(t, testTenant, "192.168.1.0/24")
	}
	return e
}

func (e *env) makeNetwork(t *testing.T, tenant Tenant, cidr string) netIDs {
	t.Helper()
	ctx := t.Context()
	cidrVPC := "192.168.0.0/16"
	v, err := e.network.CreateVPC(ctx, tenant.vpc(), vpc.CreateVPCOption{CIDR: &cidrVPC})
	if err != nil {
		t.Fatal(err)
	}
	gw := strings.TrimSuffix(cidr, "0/24") + "1"
	sn, err := e.network.CreateSubnet(ctx, tenant.vpc(), vpc.CreateSubnetOption{Name: "db", CIDR: cidr, GatewayIP: gw, VPCID: v.ID})
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.network.CreateSecurityGroup(ctx, tenant.vpc(), vpc.CreateSecurityGroupOption{Name: "db"}, false)
	if err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	return netIDs{vpc: v.ID, subnet: sn.ID, group: g.ID}
}

func (e *env) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(testDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}

func (e *env) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, testProject, method, path, body)
}

func (e *env) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+project+path, rd)
	r.Host = testHost
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func (e *env) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "golden", goldenName+".json"), status, out)
	return out
}

func decodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

// body builds a create request: a valid single MySQL 8.0 instance in
// the env's network, with fields replaced or added by "key", json pairs.
// A value of "<omit>" removes the field.
func (e *env) body(extra ...string) string {
	return e.bodyIn(e.net, extra...)
}

func (e *env) bodyIn(n netIDs, extra ...string) string {
	fields := map[string]string{
		"name":              `"rds-mysql"`,
		"datastore":         `{"type": "MySQL", "version": "8.0"}`,
		"flavor_ref":        `"rds.mysql.n1.large.2"`,
		"volume":            `{"type": "CLOUDSSD", "size": 100}`,
		"region":            `"ap-southeast-1"`,
		"availability_zone": `"ap-southeast-1a"`,
		"vpc_id":            `"` + n.vpc + `"`,
		"subnet_id":         `"` + n.subnet + `"`,
		"security_group_id": `"` + n.group + `"`,
		"password":          `"Weistack@2026"`,
	}
	order := []string{"name", "datastore", "flavor_ref", "volume", "region", "availability_zone", "vpc_id", "subnet_id", "security_group_id", "password"}
	for i := 0; i+1 < len(extra); i += 2 {
		if _, ok := fields[extra[i]]; !ok {
			order = append(order, extra[i])
		}
		fields[extra[i]] = extra[i+1]
	}
	var parts []string
	for _, k := range order {
		if fields[k] != "<omit>" {
			parts = append(parts, fmt.Sprintf("%q: %s", k, fields[k]))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// mustCreate creates an instance over HTTP and returns its ID and job.
func (e *env) mustCreate(t *testing.T, body string) (string, string) {
	t.Helper()
	status, out := e.call(t, http.MethodPost, "/instances", body)
	if status != http.StatusAccepted {
		t.Fatalf("create: %d %s", status, out)
	}
	res := decodeInto[createInstanceResponse](t, out)
	return res.Instance.ID, res.JobID
}

func (e *env) instance(t *testing.T, id string) Instance {
	t.Helper()
	inst, err := e.svc.GetInstance(t.Context(), testTenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func (e *env) jobStatus(t *testing.T, id string) string {
	t.Helper()
	job, err := e.svc.GetJob(t.Context(), testTenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return job.Name + ":" + job.Status
}

func (e *env) subnetFree(t *testing.T) int {
	t.Helper()
	sn, err := e.network.GetSubnet(t.Context(), testTenant.vpc(), e.net.subnet)
	if err != nil {
		t.Fatal(err)
	}
	return sn.AvailableIPAddressCount
}
