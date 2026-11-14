package config

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(nil, env(nil), io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Host:             "127.0.0.1",
		Port:             8780,
		Region:           "ap-southeast-1",
		ProxyDomains:     []string{"myhuaweicloud.com"},
		ProxyBypass:      DefaultProxyBypass,
		ProxyPassthrough: "loopback",
		IAM:              IAMAccept,
		ECSMaxServers:    20,
		ECSMaxVCPUs:      80,
		RDSMaxInstances:  20,
		LifecycleDelay:   2 * time.Second,
		LogLevel:         slog.LevelInfo,
		LogFormat:        "auto",
		MaxBodyBytes:     10 << 20,
		ShutdownTimeout:  10 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestLoadPrecedence(t *testing.T) {
	t.Parallel()

	vars := map[string]string{
		"WEISTACK_PORT":            "9000",
		"WEISTACK_REGION":          "af-south-1",
		"WEISTACK_HOST":            "0.0.0.0",
		"WEISTACK_PROJECT_ID":      "0123456789abcdef0123456789abcdef",
		"WEISTACK_PERSIST":         "1",
		"WEISTACK_DATA_DIR":        "/var/lib/weistack",
		"WEISTACK_SEED_DIR":        "/etc/weistack/seed",
		"WEISTACK_LIFECYCLE_DELAY": "0",
		"WEISTACK_LOG_LEVEL":       "debug",
		"WEISTACK_LOG_FORMAT":      "TEXT",
		"WEISTACK_SERVICES":        "vpc, ECS,,vpc",
		"WEISTACK_METRICS":         "true",
	}

	// Flags beat the environment; unset flags fall back to it.
	got, err := Load([]string{"-port", "9100", "-region=cn-north-4"}, env(vars), io.Discard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.Port != 9100 {
		t.Errorf("Port = %d, want flag value 9100", got.Port)
	}
	if got.Region != "cn-north-4" {
		t.Errorf("Region = %q, want flag value cn-north-4", got.Region)
	}
	if got.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want env value", got.Host)
	}
	if got.ProjectID != "0123456789abcdef0123456789abcdef" {
		t.Errorf("ProjectID = %q", got.ProjectID)
	}
	if !got.Persist || !got.Metrics {
		t.Errorf("Persist = %v, Metrics = %v, want both true", got.Persist, got.Metrics)
	}
	if got.DataDir != "/var/lib/weistack" {
		t.Errorf("DataDir = %q", got.DataDir)
	}
	if got.LifecycleDelay != 0 {
		t.Errorf("LifecycleDelay = %s, want 0", got.LifecycleDelay)
	}
	if got.SeedDir != "/etc/weistack/seed" {
		t.Errorf("SeedDir = %q", got.SeedDir)
	}
	if got.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %s, want debug", got.LogLevel)
	}
	if got.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want text", got.LogFormat)
	}
	if want := []string{"vpc", "ecs"}; !reflect.DeepEqual(got.Services, want) {
		t.Errorf("Services = %v, want %v", got.Services, want)
	}
}

func TestLoadDurationForms(t *testing.T) {
	t.Parallel()

	tests := map[string]time.Duration{
		"0":     0,
		"3":     3 * time.Second,
		"0.5":   500 * time.Millisecond,
		"250ms": 250 * time.Millisecond,
		"1m":    time.Minute,
	}
	for in, want := range tests {
		got, err := Load(nil, env(map[string]string{"WEISTACK_LIFECYCLE_DELAY": in}), io.Discard)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.LifecycleDelay != want {
			t.Errorf("%q: LifecycleDelay = %s, want %s", in, got.LifecycleDelay, want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantSub string
	}{
		{"bad env int", nil, map[string]string{"WEISTACK_PORT": "eighty"}, "WEISTACK_PORT"},
		{"bad env int64", nil, map[string]string{"WEISTACK_MAX_BODY_BYTES": "big"}, "WEISTACK_MAX_BODY_BYTES"},
		{"bad env bool", nil, map[string]string{"WEISTACK_PERSIST": "maybe"}, "WEISTACK_PERSIST"},
		{"bad env duration", nil, map[string]string{"WEISTACK_LIFECYCLE_DELAY": "soon"}, "WEISTACK_LIFECYCLE_DELAY"},
		{"port out of range", []string{"-port", "70000"}, nil, "out of range"},
		{"bad region", []string{"-region", "Mars"}, nil, "region"},
		{"bad project id", []string{"-project-id", "abc"}, nil, "32 lowercase hex"},
		{"persist without a data dir", []string{"-persist", "-data-dir", ""}, nil, "data directory"},
		{"negative delay", []string{"-lifecycle-delay", "-1s"}, nil, "negative"},
		{"zero server quota", []string{"-ecs-max-servers", "0"}, nil, "ECS quotas"},
		{"zero rds quota", []string{"-rds-max-instances", "0"}, nil, "RDS instance quota"},
		{"zero vcpu quota", nil, map[string]string{"WEISTACK_ECS_MAX_VCPUS": "0"}, "ECS quotas"},
		{"bad log level", []string{"-log-level", "loud"}, nil, "log level"},
		{"bad log format", []string{"-log-format", "xml"}, nil, "log format"},
		{"bad service name", []string{"-services", "vpc,e c s"}, nil, "service name"},
		{"zero body limit", []string{"-max-body-bytes", "0"}, nil, "max body bytes"},
		{"zero shutdown timeout", []string{"-shutdown-timeout", "0s"}, nil, "shutdown timeout"},
		{"bad service port", []string{"-service-ports", "obs"}, nil, "want service=port"},
		{"service port not a number", []string{"-service-ports", "obs=x"}, nil, "want service=port"},
		{"service port twice", []string{"-service-ports", "obs=9000,obs=9001"}, nil, "more than one port"},
		{"service port out of range", []string{"-service-ports", "obs=70000"}, nil, "out of range"},
		{"service port clash", []string{"-service-ports", "obs=9000,ecs=9000"}, nil, "already used"},
		{"service port on the main port", []string{"-service-ports", "obs=8780"}, nil, "already used"},
		{"service port bad name", []string{"-service-ports", "O B S=9000"}, nil, "not valid"},
		{"bad passthrough", []string{"-proxy-passthrough", "some"}, nil, "proxy passthrough"},
		{"bad iam mode", []string{"-iam", "strict"}, nil, "iam mode"},
		{"bad proxy domain", []string{"-proxy-domains", "not a domain"}, nil, "not a domain name"},
		{"positional argument", []string{"serve"}, nil, "unexpected argument"},
		{"unknown flag", []string{"-nope"}, nil, "not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(tt.args, env(tt.env), io.Discard)
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tt.wantSub)
			}
		})
	}
}

func TestLoadHelp(t *testing.T) {
	t.Parallel()

	var usage strings.Builder
	_, err := Load([]string{"-h"}, env(nil), &usage)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(usage.String(), "-lifecycle-delay") {
		t.Fatalf("usage does not list flags:\n%s", usage.String())
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	t.Parallel()

	err := Config{Port: -1, Region: "x", LogFormat: "yaml", ECSMaxServers: 1, ECSMaxVCPUs: 1, RDSMaxInstances: 1, ProxyPassthrough: "none", Persist: true}.Validate()
	if err == nil {
		t.Fatal("Validate succeeded, want error")
	}
	for _, sub := range []string{"port", "region", "log format", "data directory"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error does not mention %q: %v", sub, err)
		}
	}
}

func TestServicePorts(t *testing.T) {
	t.Parallel()
	got, err := Load([]string{"-service-ports", "obs=9000, ecs=9001"}, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.ServicePorts, map[string]int{"obs": 9000, "ecs": 9001}) {
		t.Fatalf("ServicePorts = %v", got.ServicePorts)
	}
	got, err = Load(nil, env(map[string]string{"WEISTACK_SERVICE_PORTS": "obs=9100"}), io.Discard)
	if err != nil || got.ServicePorts["obs"] != 9100 {
		t.Fatalf("from the environment: %v, %v", got.ServicePorts, err)
	}
}

func TestServiceEnabled(t *testing.T) {
	t.Parallel()

	all := Config{}
	if !all.ServiceEnabled("vpc") {
		t.Error("empty list should enable every service")
	}
	some := Config{Services: []string{"vpc", "ecs"}}
	if !some.ServiceEnabled("ecs") || some.ServiceEnabled("rds") {
		t.Error("subset list not honoured")
	}
}

func TestDefaultDataDir(t *testing.T) {
	t.Parallel()
	if got := DefaultDataDir(env(map[string]string{"XDG_DATA_HOME": "/xdg", "HOME": "/home/u"})); got != filepath.Join("/xdg", "weistack") {
		t.Errorf("with XDG_DATA_HOME: %q", got)
	}
	home := DefaultDataDir(env(map[string]string{"HOME": "/home/u"}))
	want := map[string]string{
		"linux":   filepath.Join("/home/u", ".local", "share", "weistack"),
		"darwin":  filepath.Join("/home/u", "Library", "Application Support", "weistack"),
		"windows": "", // from LocalAppData, not HOME
	}[runtime.GOOS]
	if w, known := want, runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows"; known && home != w {
		t.Errorf("from HOME on %s: %q, want %q", runtime.GOOS, home, w)
	}
	if runtime.GOOS != "windows" {
		if got := DefaultDataDir(env(nil)); got != "" {
			t.Errorf("without HOME: %q, want empty", got)
		}
	}

	// It is the -data-dir default; the environment variable still wins.
	cfg, err := Load(nil, env(map[string]string{"XDG_DATA_HOME": "/xdg"}), io.Discard)
	if err != nil || cfg.DataDir != filepath.Join("/xdg", "weistack") {
		t.Errorf("Load default data dir = %q, %v", cfg.DataDir, err)
	}
	cfg, err = Load(nil, env(map[string]string{"XDG_DATA_HOME": "/xdg", "WEISTACK_DATA_DIR": "/data"}), io.Discard)
	if err != nil || cfg.DataDir != "/data" {
		t.Errorf("WEISTACK_DATA_DIR = %q, %v", cfg.DataDir, err)
	}
	// Without persistence no directory is needed.
	if _, err := Load([]string{"-data-dir", ""}, env(nil), io.Discard); err != nil {
		t.Errorf("an empty data dir without -persist: %v", err)
	}
}

func TestLogFormats(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"json", "text", "auto", "TEXT"} {
		if _, err := Load([]string{"-log-format", f}, env(nil), io.Discard); err != nil {
			t.Errorf("-log-format %s: %v", f, err)
		}
	}
}

func TestProxyBypass(t *testing.T) {
	t.Parallel()
	cfg, err := Load([]string{"-proxy-bypass", "tools.*.example.com, {region}-cli.obs.{region}.example.com"}, env(nil), io.Discard)
	if err != nil || len(cfg.ProxyBypass) != 2 || cfg.ProxyBypass[0] != "tools.*.example.com" {
		t.Fatalf("custom bypass = %v, %v", cfg.ProxyBypass, err)
	}
	if cfg, err := Load([]string{"-proxy-bypass", ""}, env(nil), io.Discard); err != nil || len(cfg.ProxyBypass) != 0 {
		t.Fatalf("an empty bypass turns it off: %v, %v", cfg.ProxyBypass, err)
	}
	if _, err := Load([]string{"-proxy-bypass", "ex*mple.com"}, env(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "proxy bypass") {
		t.Fatalf("an invalid pattern: %v", err)
	}
}
