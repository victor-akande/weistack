package policy

import (
	"strings"
	"testing"
)

func sources(t *testing.T, docs ...string) []Source {
	t.Helper()
	out := make([]Source, len(docs))
	for i, d := range docs {
		out[i] = Source{Name: "p" + string(rune('0'+i)), Policy: mustParse(t, d)}
	}
	return out
}

func TestEvaluateDenyOverridesAllow(t *testing.T) {
	t.Parallel()
	allow := `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:*"]}]}`
	deny := `{"Version":"5.0","Statement":[{"Sid":"noDelete","Effect":"Deny","Action":["vpc:vpcs:delete"]}]}`
	srcs := sources(t, allow, deny)

	d := Evaluate(Request{Action: "vpc:vpcs:list"}, srcs)
	if !d.Allowed || d.Policy != "p0" {
		t.Fatalf("list: %+v", d)
	}
	d = Evaluate(Request{Action: "vpc:vpcs:delete"}, srcs)
	if d.Allowed || !d.Explicit || d.Policy != "p1" || d.Sid != "noDelete" {
		t.Fatalf("delete: %+v", d)
	}
	if d.Failure() != "explicit deny by identity-based policy" {
		t.Fatalf("failure %q", d.Failure())
	}
	d = Evaluate(Request{Action: "ecs:cloudServers:list"}, srcs)
	if d.Allowed || d.Explicit || d.Failure() != "implicit deny by identity-based policy" {
		t.Fatalf("other service: %+v", d)
	}
	if d := Evaluate(Request{Action: "vpc:vpcs:list"}, nil); d.Allowed {
		t.Fatal("no policies allowed a request")
	}
}

func TestEvaluateAliases(t *testing.T) {
	t.Parallel()
	classic := sources(t, `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["ecs:cloudServers:create"]}]}`)
	v5 := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["ecs:cloudServers:create"]}]}`)
	req := Request{Action: "ecs:cloudServers:createServers", Aliases: []string{"ecs:cloudServers:create"}}

	if !Evaluate(req, classic).Allowed {
		t.Error("a classic policy did not match the alias")
	}
	if Evaluate(req, v5).Allowed {
		t.Error("a 5.0 policy matched an alias")
	}
	// Actions are case-insensitive.
	ci := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["ECS:CLOUDSERVERS:CREATESERVERS"]}]}`)
	if !Evaluate(req, ci).Allowed {
		t.Error("action matching is case-sensitive")
	}
}

func TestEvaluateNotAction(t *testing.T) {
	t.Parallel()
	// Huawei's example: everything except IAM.
	srcs := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","NotAction":["IAM:*:*"]}]}`)
	if !Evaluate(Request{Action: "vpc:vpcs:create"}, srcs).Allowed {
		t.Error("vpc denied")
	}
	if Evaluate(Request{Action: "iam:users:createUserV5"}, srcs).Allowed {
		t.Error("iam allowed")
	}
}

func TestEvaluateResources(t *testing.T) {
	t.Parallel()
	vpc := "vpc:ap-southeast-1:acct:vpc:v1"
	other := "vpc:ap-southeast-1:acct:vpc:v2"
	srcs := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:*"],"Resource":["vpc:*:*:VPC:v1"]}]}`)

	if !Evaluate(Request{Action: "vpc:vpcs:get", Resources: []string{vpc}}, srcs).Allowed {
		t.Error("named resource denied (resource types are case-insensitive)")
	}
	if Evaluate(Request{Action: "vpc:vpcs:get", Resources: []string{other}}, srcs).Allowed {
		t.Error("other resource allowed")
	}
	// An action on no particular resource needs Resource *.
	if Evaluate(Request{Action: "vpc:vpcs:list"}, srcs).Allowed {
		t.Error("resource-less action allowed by a resource-specific statement")
	}
	star := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["vpc:*:*"],"Resource":["*"]}]}`)
	if !Evaluate(Request{Action: "vpc:vpcs:list"}, star).Allowed {
		t.Error("Resource * denied a resource-less action")
	}
	// Every resource must be allowed.
	both := Request{Action: "vpc:subnets:create", Resources: []string{vpc, other}}
	if Evaluate(both, srcs).Allowed {
		t.Error("a request with one unallowed resource was allowed")
	}
	// NotResource.
	not := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Deny","Action":["vpc:*:*"],"NotResource":["vpc:*:*:vpc:v1"]},{"Effect":"Allow","Action":["*"]}]}`)
	if !Evaluate(Request{Action: "vpc:vpcs:get", Resources: []string{vpc}}, not).Allowed {
		t.Error("NotResource denied the excluded resource")
	}
	if Evaluate(Request{Action: "vpc:vpcs:get", Resources: []string{other}}, not).Allowed {
		t.Error("NotResource did not deny another resource")
	}
	// OBS objects: the path holds the bucket and key.
	obs := sources(t, `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["obs:object:*"],"Resource":["obs:*:*:object:my-bucket/my-object/*"]}]}`)
	if !Evaluate(Request{Action: "obs:object:getObject", Resources: []string{"obs:::object:my-bucket/my-object/a/b"}}, obs).Allowed {
		t.Error("object under the prefix denied")
	}
	if Evaluate(Request{Action: "obs:object:getObject", Resources: []string{"obs:::object:my-bucket/other"}}, obs).Allowed {
		t.Error("object outside the prefix allowed")
	}
	// Classic agency resources match no service request.
	agency := sources(t, `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["*:*:*"],"Resource":{"uri":["/iam/agencies/x"]}}]}`)
	if Evaluate(Request{Action: "vpc:vpcs:list"}, agency).Allowed {
		t.Error("an agency resource allowed a service request")
	}
	// ...but match a request to assume that agency, by ID or name.
	assume := Request{Action: "iam:tokens:assume", URIs: []string{"/iam/agencies/0123", "/iam/agencies/X"}}
	if !Evaluate(assume, agency).Allowed {
		t.Error("an agency resource did not allow assuming it")
	}
	if Evaluate(Request{Action: "iam:tokens:assume", URIs: []string{"/iam/agencies/y"}}, agency).Allowed {
		t.Error("an agency resource allowed assuming another agency")
	}
	wild := sources(t, `{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["iam:tokens:assume"],"Resource":{"uri":["/iam/agencies/*"]}}]}`)
	if !Evaluate(assume, wild).Allowed {
		t.Error("a wildcard agency resource did not allow assuming")
	}
}

func TestEvaluateRoles(t *testing.T) {
	t.Parallel()
	// A role's statements apply to every resource.
	srcs := sources(t, `{"Version":"1.0","Statement":[{"Effect":"Allow","Action":["vpc:*:*"]}],"Depends":[{"catalog":"BASE","display_name":"Tenant Guest"}]}`)
	if !Evaluate(Request{Action: "vpc:vpcs:get", Resources: []string{"vpc:r:a:vpc:v"}}, srcs).Allowed {
		t.Error("role did not allow")
	}
}

func TestEvaluateVariables(t *testing.T) {
	t.Parallel()
	srcs := sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["iam:credentials:*"],"Resource":["iam::${g:DomainId}:user:${g:UserName}"]}]}`)
	keys := map[string][]string{"g:domainid": {"acct"}, "g:username": {"alice"}}
	own := Request{Action: "iam:credentials:createCredentialV5", Resources: []string{"iam::acct:user:alice"}, Keys: keys}
	if !Evaluate(own, srcs).Allowed {
		t.Error("own user denied")
	}
	own.Resources = []string{"iam::acct:user:bob"}
	if Evaluate(own, srcs).Allowed {
		t.Error("other user allowed")
	}
	own.Keys = nil
	if Evaluate(own, srcs).Allowed {
		t.Error("a statement applied though its variable could not be substituted")
	}
}

func TestConditions(t *testing.T) {
	t.Parallel()
	cond := func(c string) []Source {
		return sources(t, `{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["*"],"Condition":`+c+`}]}`)
	}
	keys := func(kv ...string) map[string][]string {
		m := map[string][]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			k := strings.ToLower(kv[i])
			if kv[i+1] == "" {
				m[k] = []string{}
				continue
			}
			m[k] = append(m[k], kv[i+1])
		}
		return m
	}
	for _, tc := range []struct {
		name string
		cond string
		keys map[string][]string
		want bool
	}{
		{"equals", `{"StringEquals":{"g:UserName":["alice"]}}`, keys("g:UserName", "alice"), true},
		{"equals is case-sensitive", `{"StringEquals":{"g:UserName":["alice"]}}`, keys("g:UserName", "Alice"), false},
		{"key names are case-insensitive", `{"StringEquals":{"G:USERNAME":["alice"]}}`, keys("g:UserName", "alice"), true},
		{"values OR", `{"StringEquals":{"g:UserName":["bob","alice"]}}`, keys("g:UserName", "alice"), true},
		{"keys AND", `{"StringEquals":{"g:UserName":["alice"],"g:DomainName":["d"]}}`, keys("g:UserName", "alice", "g:DomainName", "x"), false},
		{"operators AND", `{"StringEquals":{"g:UserName":["alice"]},"Bool":{"g:MFAPresent":["true"]}}`, keys("g:UserName", "alice", "g:MFAPresent", "false"), false},
		{"absent key", `{"StringEquals":{"g:UserName":["alice"]}}`, nil, false},
		{"IfExists absent", `{"StringEqualsIfExists":{"g:UserName":["alice"]}}`, nil, true},
		{"IfExists present", `{"StringEqualsIfExists":{"g:UserName":["alice"]}}`, keys("g:UserName", "bob"), false},
		{"negated absent", `{"StringNotEquals":{"g:UserName":["alice"]}}`, nil, true},
		{"negated NOR", `{"StringNotEquals":{"g:UserName":["alice","bob"]}}`, keys("g:UserName", "bob"), false},
		{"negated other", `{"StringNotEquals":{"g:UserName":["alice","bob"]}}`, keys("g:UserName", "carol"), true},
		{"ignore case", `{"StringEqualsIgnoreCase":{"g:UserName":["ALICE"]}}`, keys("g:UserName", "alice"), true},
		{"match", `{"StringMatch":{"g:UserName":["dev-*"]}}`, keys("g:UserName", "dev-alice"), true},
		{"not match", `{"StringNotMatch":{"g:UserName":["dev-*"]}}`, keys("g:UserName", "dev-alice"), false},
		{"start with", `{"StringStartWith":{"g:UserName":["DEV"]}}`, keys("g:UserName", "dev-alice"), true},
		{"end with", `{"StringEndWith":{"g:UserName":["ICE"]}}`, keys("g:UserName", "dev-alice"), true},
		{"number", `{"NumberLessThan":{"a:n":["10"]}}`, keys("a:n", "9.5"), true},
		{"number equal", `{"NumberGreaterThanEquals":{"a:n":["10"]}}`, keys("a:n", "10"), true},
		{"number not a number", `{"NumberLessThan":{"a:n":["10"]}}`, keys("a:n", "x"), false},
		{"date", `{"DateLessThan":{"g:CurrentTime":["2026-01-01T00:00:00Z"]}}`, keys("g:CurrentTime", "2025-12-31T23:59:59Z"), true},
		{"date after", `{"DateLessThan":{"g:CurrentTime":["2026-01-01T00:00:00Z"]}}`, keys("g:CurrentTime", "2026-01-01T00:00:00Z"), false},
		{"bool", `{"Bool":{"g:MFAPresent":["false"]}}`, keys("g:MFAPresent", "false"), true},
		{"null true absent", `{"Null":{"g:ResourceTag/env":["true"]}}`, nil, true},
		{"null true present", `{"Null":{"g:ResourceTag/env":["true"]}}`, keys("g:ResourceTag/env", "prod"), false},
		{"null false present", `{"Null":{"g:ResourceTag/env":["false"]}}`, keys("g:ResourceTag/env", "prod"), true},
		{"ip in", `{"IpAddress":{"g:SourceIp":["10.0.0.0/8"]}}`, keys("g:SourceIp", "10.1.2.3"), true},
		{"ip out", `{"IpAddress":{"g:SourceIp":["10.0.0.0/8"]}}`, keys("g:SourceIp", "192.168.0.1"), false},
		{"not ip", `{"NotIpAddress":{"g:SourceIp":["10.0.0.0/8","127.0.0.1"]}}`, keys("g:SourceIp", "127.0.0.1"), false},
		{"for all values", `{"ForAllValues:StringEquals":{"g:TagKeys":["a","b"]}}`, keys("g:TagKeys", "a", "g:TagKeys", "b"), true},
		{"for all values extra", `{"ForAllValues:StringEquals":{"g:TagKeys":["a","b"]}}`, keys("g:TagKeys", "a", "g:TagKeys", "c"), false},
		{"for all values empty", `{"ForAllValues:StringEquals":{"g:TagKeys":["a"]}}`, keys("g:TagKeys", ""), true},
		{"for all values missing", `{"ForAllValues:StringEquals":{"g:TagKeys":["a"]}}`, nil, false},
		{"for any value", `{"ForAnyValue:StringEquals":{"g:TagKeys":["a"]}}`, keys("g:TagKeys", "z", "g:TagKeys", "a"), true},
		{"for any value none", `{"ForAnyValue:StringEquals":{"g:TagKeys":["a"]}}`, keys("g:TagKeys", "z"), false},
		{"for any value missing", `{"ForAnyValue:StringEquals":{"g:TagKeys":["a"]}}`, nil, false},
		{"variable value", `{"StringEquals":{"g:ProjectName":["${g:UserName}"]}}`, keys("g:ProjectName", "alice", "g:UserName", "alice"), true},
		{"variable missing", `{"StringEquals":{"g:ProjectName":["${g:UserName}"]}}`, keys("g:ProjectName", "alice"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Evaluate(Request{Action: "a:b:c", Keys: tc.keys}, cond(tc.cond)).Allowed
			if got != tc.want {
				t.Fatalf("allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	var srcs []Source
	for _, d := range []string{
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["ecs:*:get*","ecs:*:list*"]}]}`,
		`{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["vpc:*:*"]},{"Effect":"Deny","Action":["vpc:securityGroups:*"]}]}`,
		`{"Version":"5.0","Statement":[{"Effect":"Allow","Action":["obs:object:*"],"Resource":["obs:*:*:object:bucket/*"],"Condition":{"StringEquals":{"g:UserName":["alice"]}}}]}`,
	} {
		p, err := Parse([]byte(d))
		if err != nil {
			b.Fatal(err)
		}
		srcs = append(srcs, Source{Name: "p", Policy: p})
	}
	req := Request{
		Action: "vpc:vpcs:get", Resources: []string{"vpc:ap-southeast-1:acct:vpc:abc"},
		Keys: map[string][]string{"g:username": {"alice"}},
	}
	b.ReportAllocs()
	for b.Loop() {
		if !Evaluate(req, srcs).Allowed {
			b.Fatal("denied")
		}
	}
}
