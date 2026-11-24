package server

import (
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/faults"
)

// TestGatewayErrorsHaveHints: the errors a client most often meets keep
// Huawei's exact body and say what to do in the hint header.
func TestGatewayErrorsHaveHints(t *testing.T) {
	t.Parallel()

	for name, e := range map[string]*apierr.Error{
		"no credentials":    errNoCredentials,
		"bad signature":     errBadSignature,
		"locked":            errLocked,
		"bad token":         errBadToken,
		"expired token":     errTokenExpired,
		"unknown key":       errUnknownKey("AK"),
		"OBS unknown key":   errOBSUnknownKey,
		"OBS bad signature": errOBSBadSignature,
		"OBS clock":         errOBSSkewed,
		"no such API":       errNoSuchAPI,
	} {
		if e.Hint == "" {
			t.Errorf("%s has no hint", name)
		}
		if strings.Contains(e.Message, e.Hint) {
			t.Errorf("%s: the hint is in the message", name)
		}
	}
}

func TestInjectedFaultsNameTheirRule(t *testing.T) {
	t.Parallel()

	for _, r := range []faults.Rule{
		{ID: "7", Status: 429},
		{ID: "8", Status: 503},
		{ID: "9", Status: 500, Code: "VPC.0001", Message: "custom"},
	} {
		for _, svc := range []string{"vpc", "obs"} {
			e := faultError(svc, r)
			if !strings.Contains(e.Hint, "fault rule "+r.ID) {
				t.Errorf("%s %+v: hint %q", svc, r, e.Hint)
			}
		}
	}
	if errThrottled.Hint != "" {
		t.Error("faultError changed the shared errThrottled")
	}
}
