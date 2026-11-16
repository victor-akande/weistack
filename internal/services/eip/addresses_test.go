package eip

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

func addrNewService(t *testing.T) *Service {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := lifecycle.New(lifecycle.Options{Logger: log})
	svc, err := New(Deps{
		Store:  store.NewMemory(),
		Engine: engine,
		IDs:    ids.NewSeeded(1),
		Logger: log,
		Ports:  pipPortStub{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func addrCodeOf(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestAddressPoolOrderAndExhaustion(t *testing.T) {
	t.Parallel()

	if len(defaultAddressPool) != 762 {
		t.Fatalf("len(defaultAddressPool) = %d, want 762", len(defaultAddressPool))
	}
	spotChecks := []struct {
		idx  int
		want string
	}{
		{0, "192.0.2.1"},
		{253, "192.0.2.254"},
		{254, "198.51.100.1"},
		{507, "198.51.100.254"},
		{508, "203.0.113.1"},
		{761, "203.0.113.254"},
	}
	for _, tc := range spotChecks {
		if got := defaultAddressPool[tc.idx]; got != tc.want {
			t.Errorf("defaultAddressPool[%d] = %q, want %q", tc.idx, got, tc.want)
		}
	}

	svc := addrNewService(t)
	svc.pool = []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	tenant := Tenant{Region: "ap-southeast-1", ProjectID: "0123456789abcdef0123456789abcdef"}

	for i, want := range svc.pool {
		got, err := svc.claimAddress(t.Context(), tenant, "pip-"+want, "")
		if err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
		if got != want {
			t.Fatalf("claim %d = %q, want %q", i, got, want)
		}
	}

	if _, err := svc.claimAddress(t.Context(), tenant, "pip-extra", ""); addrCodeOf(err) != "VPC.0532" {
		t.Fatalf("exhausted claim err = %v, want VPC.0532", err)
	}

	if err := svc.releaseAddress(t.Context(), tenant.Region, "198.51.100.1"); err != nil {
		t.Fatalf("releaseAddress: %v", err)
	}
	got, err := svc.claimAddress(t.Context(), tenant, "pip-reclaimed", "")
	if err != nil || got != "198.51.100.1" {
		t.Fatalf("reclaim = %q, %v; want 198.51.100.1", got, err)
	}
}

func TestAddressRequestedAndCrossProjectUniqueness(t *testing.T) {
	t.Parallel()
	svc := addrNewService(t)
	projA := Tenant{Region: "ap-southeast-1", ProjectID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	projB := Tenant{Region: "ap-southeast-1", ProjectID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	otherRegion := Tenant{Region: "cn-north-4", ProjectID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	// Auto-allocation across projects in the same region never collides.
	a1, err := svc.claimAddress(t.Context(), projA, "pip-a1", "")
	if err != nil || a1 != "192.0.2.1" {
		t.Fatalf("projA claim = %q, %v; want 192.0.2.1", a1, err)
	}
	b1, err := svc.claimAddress(t.Context(), projB, "pip-b1", "")
	if err != nil || b1 != "192.0.2.2" {
		t.Fatalf("projB claim = %q, %v; want 192.0.2.2", b1, err)
	}

	tests := []struct {
		name      string
		tenant    Tenant
		requested string
		wantCode  string
	}{
		{"valid range 1", projA, "192.0.2.10", ""},
		{"valid range 2", projA, "198.51.100.20", ""},
		{"valid range 3", projB, "203.0.113.254", ""},
		{"already claimed in same project", projA, "192.0.2.1", "VPC.0522"},
		{"already claimed in other project", projB, "192.0.2.1", "VPC.0522"},
		{"same address in different region", otherRegion, "192.0.2.1", ""},
		{"network address .0", projA, "192.0.2.0", "VPC.0522"},
		{"broadcast address .255", projA, "192.0.2.255", "VPC.0522"},
		{"outside pool", projA, "10.0.0.1", "VPC.0522"},
		{"malformed ip", projA, "not-an-ip", "VPC.0522"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.claimAddress(t.Context(), tc.tenant, "pip-"+tc.name, tc.requested)
			if tc.wantCode == "" {
				if err != nil || got != tc.requested {
					t.Fatalf("claimAddress(%q) = %q, %v; want %q, nil", tc.requested, got, err, tc.requested)
				}
			} else if addrCodeOf(err) != tc.wantCode {
				t.Fatalf("claimAddress(%q) err = %v, want %s", tc.requested, err, tc.wantCode)
			}
		})
	}
}
