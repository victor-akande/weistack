package policy

import (
	"errors"
	"slices"
	"testing"
)

func TestParseTrust(t *testing.T) {
	t.Parallel()
	good := []string{
		`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["sts:agencies:assume"],"Principal":{"IAM":["123456789012"]}}]}`,
		`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":"sts:agencies:assume","Principal":{"Service":"service.OBS"}}]}`,
		`{"Version":"5.0","Statement":[{"Effect":"Deny","Action":["sts:agencies:assume"],"NotPrincipal":{"IAM":["iam::123456789012:user:alice"]},
			"Condition":{"Bool":{"g:MFAPresent":["true"]}}}]}`,
	}
	for _, doc := range good {
		if _, err := ParseTrust([]byte(doc)); err != nil {
			t.Errorf("ParseTrust(%s): %v", doc, err)
		}
	}
	bad := map[string]string{
		"no principal":   `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["sts:agencies:assume"]}]}`,
		"both":           `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":{"IAM":["1"]},"NotPrincipal":{"IAM":["2"]}}]}`,
		"unknown kind":   `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":{"AWS":["1"]}}]}`,
		"empty list":     `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":{"IAM":[]}}]}`,
		"classic":        `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":{"IAM":["1"]}}]}`,
		"not an object":  `[]`,
		"bad statement":  `{"Version":"5.0","Statement":[{"Effect":"Maybe","Action":["a:b:c"],"Principal":{"IAM":["1"]}}]}`,
		"extra element":  `{"Version":"5.0","Id":"x","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":{"IAM":["1"]}}]}`,
		"principal kind": `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":"*"}]}`,
	}
	for name, doc := range bad {
		var pe *Error
		if _, err := ParseTrust([]byte(doc)); !errors.As(err, &pe) {
			t.Errorf("%s: ParseTrust = %v, want a *policy.Error", name, err)
		}
	}
	// An identity policy may not name principals.
	if _, err := Parse([]byte(good[0])); err == nil {
		t.Error("Parse accepted a Principal in an identity policy")
	}
}

func TestEvaluateTrust(t *testing.T) {
	t.Parallel()
	p, err := ParseTrust([]byte(`{"Version":"5.0","Statement":[
		{"Effect":"Allow","Action":["sts:agencies:assume"],"Principal":{"IAM":["111","iam::222:user:bob"],"Service":["service.OBS"]}},
		{"Effect":"Deny","Action":["sts:agencies:assume"],"Principal":{"IAM":["iam::111:user:mallory"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.TrustedAccounts(); !slices.Equal(got, []string{"111"}) {
		t.Errorf("TrustedAccounts = %v", got)
	}
	src := []Source{{Name: "trust", Policy: p}}
	for _, c := range []struct {
		name   string
		caller *Caller
		want   bool
	}{
		{"an account's user", &Caller{AccountID: "111", URN: "iam::111:user:alice"}, true},
		{"denied by URN", &Caller{AccountID: "111", URN: "iam::111:user:mallory"}, false},
		{"a user named by URN", &Caller{AccountID: "222", URN: "iam::222:user:bob"}, true},
		{"another user of that account", &Caller{AccountID: "222", URN: "iam::222:user:eve"}, false},
		{"a service", &Caller{Service: "service.obs"}, true},
		{"another service", &Caller{Service: "service.ECS"}, false},
		{"no caller", nil, false},
	} {
		d := Evaluate(Request{Action: "sts:agencies:assume", Caller: c.caller}, src)
		if d.Allowed != c.want {
			t.Errorf("%s: allowed = %v, want %v", c.name, d.Allowed, c.want)
		}
	}

	// NotPrincipal applies to everyone but those named.
	np, err := ParseTrust([]byte(`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["sts:agencies:assume"],"NotPrincipal":{"IAM":["333"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if Evaluate(Request{Action: "sts:agencies:assume", Caller: &Caller{AccountID: "333"}}, []Source{{Policy: np}}).Allowed ||
		!Evaluate(Request{Action: "sts:agencies:assume", Caller: &Caller{AccountID: "444"}}, []Source{{Policy: np}}).Allowed {
		t.Error("NotPrincipal did not exclude only the account it names")
	}
}
