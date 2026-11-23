package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestAdminCommandSignsUnderEnforce(t *testing.T) {
	t.Parallel()
	tls := t.TempDir()
	vars := map[string]string{"WEISTACK_IAM": "enforce", "WEISTACK_TLS_DIR": tls}
	inst := startInstance(t, vars)
	_, port, _ := net.SplitHostPort(inst.addr)

	if status, _ := inst.get(t, "/_weistack/services"); status != http.StatusUnauthorized {
		t.Fatalf("unsigned GET /_weistack/services = %d, want 401", status)
	}
	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := Run(context.Background(), Env{
			Args: append([]string{"admin"}, args...), Getenv: func(k string) string { return vars[k] },
			Stdout: &out, Stderr: &bytes.Buffer{},
		})
		return out.String(), err
	}

	out, err := run("GET", "services", "-port", port)
	if err != nil {
		t.Fatal(err)
	}
	var services struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(out), &services); err != nil || services.ProjectID == "" {
		t.Fatalf("admin GET services = %q, %v", out, err)
	}
	if out, err = run("post", "/_weistack/accounts", `{"name":"partner"}`, "-port", port); err != nil || !strings.Contains(out, `"access_key"`) {
		t.Fatalf("admin POST accounts = %q, %v", out, err)
	}
	if _, err = run("GET", "nothing", "-port", port); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("admin GET nothing: %v, want a 404 error", err)
	}
	for _, args := range [][]string{{}, {"GET"}, {"-port", port}} {
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("admin %q: %v, want the usage", args, err)
		}
	}
}
