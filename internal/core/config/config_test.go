package config

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"reflect"
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
		Host:            "127.0.0.1",
		Port:            8780,
		Region:          "ap-southeast-1",
		DataDir:         "/data",
		ECSMaxServers:   20,
		ECSMaxVCPUs:     80,
		RDSMaxInstances: 20,
		LifecycleDelay:  2 * time.Second,
		LogLevel:        slog.LevelInfo,
		LogFormat:       "json",
		MaxBodyBytes:    10 << 20,
		ShutdownTimeout: 10 * time.Second,
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
		{"empty data dir", []string{"-data-dir", ""}, nil, "data directory"},
		{"negative delay", []string{"-lifecycle-delay", "-1s"}, nil, "negative"},
		{"zero server quota", []string{"-ecs-max-servers", "0"}, nil, "ECS quotas"},
		{"zero rds quota", []string{"-rds-max-instances", "0"}, nil, "RDS instance quota"},
		{"zero vcpu quota", nil, map[string]string{"WEISTACK_ECS_MAX_VCPUS": "0"}, "ECS quotas"},
		{"bad log level", []string{"-log-level", "loud"}, nil, "log level"},
		{"bad log format", []string{"-log-format", "xml"}, nil, "log format"},
		{"bad service name", []string{"-services", "vpc,e c s"}, nil, "service name"},
		{"zero body limit", []string{"-max-body-bytes", "0"}, nil, "max body bytes"},
		{"zero shutdown timeout", []string{"-shutdown-timeout", "0s"}, nil, "shutdown timeout"},
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

	err := Config{Port: -1, Region: "x", LogFormat: "yaml", ECSMaxServers: 1, ECSMaxVCPUs: 1, RDSMaxInstances: 1}.Validate()
	if err == nil {
		t.Fatal("Validate succeeded, want error")
	}
	for _, sub := range []string{"port", "region", "log format", "data directory"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error does not mention %q: %v", sub, err)
		}
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
