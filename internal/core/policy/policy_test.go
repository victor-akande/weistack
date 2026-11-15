package policy

import (
	"errors"
	"testing"
)

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse(%s): %v", doc, err)
	}
	return p
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		doc  string
		kind ErrorKind
	}{
		{"not JSON", `nope`, ErrJSON},
		{"array", `[]`, ErrJSON},
		{"no version", `{"Statement":[]}`, ErrVersion},
		{"bad version", `{"Version":"2.0","Statement":[]}`, ErrVersion},
		{"5.0 extra element", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"]}],"Depends":[]}`, ErrElement},
		{"empty statements", `{"Version":"1.1","Statement":[]}`, ErrStatement},
		{"statement not object", `{"Version":"1.1","Statement":["x"]}`, ErrStatement},
		{"5.0 unknown element", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Principal":"*"}]}`, ErrElement},
		{"5.0 lower-case effect", `{"Version":"5.0","Statement":[{"Effect":"allow","Action":["a:b:c"]}]}`, ErrEffect},
		{"bad effect", `{"Version":"1.1","Statement":[{"Effect":"Maybe","Action":["a:b:c"]}]}`, ErrEffect},
		{"no action", `{"Version":"1.1","Statement":[{"Effect":"Allow"}]}`, ErrAction},
		{"both actions", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"NotAction":["x:y:z"]}]}`, ErrAction},
		{"empty action", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":[""]}]}`, ErrAction},
		{"bad resource", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Resource":["vpc:x"]}]}`, ErrResource},
		{"classic NotResource", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"NotResource":["*"]}]}`, ErrResource},
		{"unknown operator", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"StringSortOf":{"g:UserName":["x"]}}}]}`, ErrOperator},
		{"classic value not list", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"StringEquals":{"g:UserName":"x"}}}]}`, ErrConditionList},
		{"bad key", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"StringEquals":{"UserName":["x"]}}}]}`, ErrConditionKey},
		{"bad date", `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"DateLessThan":{"g:CurrentTime":["soon"]}}}]}`, ErrConditionValue},
		{"bad number", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"NumberEquals":{"a:n":["one"]}}}]}`, ErrConditionValue},
		{"bad bool", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"Bool":{"g:MFAPresent":["yes"]}}}]}`, ErrConditionValue},
		{"bad ip", `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"IpAddress":{"g:SourceIp":["10.0.0.0/33"]}}}]}`, ErrConditionValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tc.doc))
			var pe *Error
			if !errors.As(err, &pe) || pe.Kind != tc.kind {
				t.Fatalf("Parse = %v, want kind %d", err, tc.kind)
			}
		})
	}
}

func TestParseAccepts(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{
		// Huawei's documented examples (iam_01_0019, iam_01_0934).
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["obs:bucket:ListAllMyBuckets","obs:bucket:HeadBucket","obs:bucket:ListBucket","obs:bucket:GetBucketLocation"],
		  "Condition":{"StringEndWithIfExists":{"g:UserName":["specialCharacter"]},"Bool":{"g:MFAPresent":["true"]}},"Resource":["obs:*:*:bucket:*"]}]}`,
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["iam:roles:createRoles"],
		  "Condition":{"DateGreaterThan":{"g:CurrentTime":["2023-03-01T00:00:00Z"]},"DateLessThan":{"g:CurrentTime":["2023-03-30T00:00:00Z"]}}}]}`,
		`{"Version":"5.0","Statement":[{"Effect":"Allow","NotAction":["IAM:*:*"]}]}`,
		// A role with Depends (iam_01_0601).
		`{"Version":"1.0","Statement":[{"Effect":"Allow","Action":["DNS:Zone:*"]}],"Depends":[{"catalog":"BASE","display_name":"Tenant Guest"}]}`,
		// Classic agency resources (the object form).
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["iam:agencies:assume"],"Resource":{"uri":["/iam/agencies/x"]}}]}`,
		// Numbers and booleans as JSON scalars, a single string in 5.0.
		`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":"ecs:*:*","Condition":{"NumberLessThan":{"ecs:n":[3]},"Bool":{"g:MFAPresent":true}}}]}`,
		`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["a:b:c"],"Condition":{"NumericLessThanEquals":{"a:n":["3"]}}}]}`,
	} {
		mustParse(t, doc)
	}
}

func TestGlob(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"a*c", "abbbc", true},
		{"a*c", "abbbd", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "aéc", true},
		{"*:*:get*", "vpc:vpcs:get", true},
		{"*:*:get*", "vpc:vpcs:list", false},
		{"iam:*:*", "iam::createaccesskey", true},
		{"*credentialv5", "iam:credentials:createcredentialv5", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"**", "x", true},
	} {
		if got := glob(tc.pattern, tc.s); got != tc.want {
			t.Errorf("glob(%q, %q) = %v", tc.pattern, tc.s, got)
		}
	}
}

func TestSubstitute(t *testing.T) {
	t.Parallel()
	keys := map[string][]string{"g:username": {"alice"}, "g:tagkeys": {"a", "b"}}
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"plain", "plain", true},
		{"iam::1:user:${g:UserName}", "iam::1:user:alice", true},
		{"${g:Missing, 'dflt'}", "dflt", true},
		{"${g:Missing, 'it''s'}", "it's", true},
		{"${*}${?}${$}", "*?$", true},
		{"${g:Missing}", "", false},
		{"${g:TagKeys}", "", false},
		{"${g:Missing, dflt}", "", false},
	} {
		got, ok := substitute(tc.in, keys)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("substitute(%q) = %q, %v", tc.in, got, ok)
		}
	}
}
