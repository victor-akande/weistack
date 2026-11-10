package golden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "g.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const sample = `{
  "source": "docs",
  "status": 200,
  "body": {
    "vpc": {
      "id": "<uuid>",
      "name": "vpc",
      "status": "CREATING",
      "routes": [],
      "tenant_id": "<hex32>",
      "created_at": "<time>",
      "updated_at": "<time-z>",
      "enabled": false,
      "count": 251,
      "note": "<string>",
      "extra": "<any>"
    }
  }
}`

const matching = `{"vpc":{"id":"99d9d709-8478-4b46-9f3f-2206b1023fd3","name":"vpc","status":"CREATING","routes":[],
"tenant_id":"087679f0aa80d32a2f4ec0172f5e902b","created_at":"2022-12-15T02:25:11","updated_at":"2022-12-15T02:25:11Z",
"enabled":false,"count":251,"note":"","extra":null}}`

func TestCompareMatches(t *testing.T) {
	t.Parallel()
	if problems := Compare(write(t, sample), 200, []byte(matching)); len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
}

func TestCompareFindsDifferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		mutate  func(string) string
		wantSub string
	}{
		{"wrong status", 201, func(s string) string { return s }, "status = 201, want 200"},
		{"missing field", 200, func(s string) string { return strings.Replace(s, `"name":"vpc",`, "", 1) }, "body.vpc.name is missing"},
		{"extra field", 200, func(s string) string { return strings.Replace(s, `"name":"vpc"`, `"name":"vpc","surprise":1`, 1) }, "body.vpc.surprise is not in the real response"},
		{"wrong value", 200, func(s string) string { return strings.Replace(s, "CREATING", "OK", 1) }, `body.vpc.status = "OK", want "CREATING"`},
		{"wrong type", 200, func(s string) string { return strings.Replace(s, `"enabled":false`, `"enabled":"false"`, 1) }, "body.vpc.enabled is a string, want a boolean"},
		{"null instead of array", 200, func(s string) string { return strings.Replace(s, `"routes":[]`, `"routes":null`, 1) }, "body.vpc.routes is null, want an array"},
		{"array length", 200, func(s string) string { return strings.Replace(s, `"routes":[]`, `"routes":[1]`, 1) }, "body.vpc.routes has 1 elements, want 0"},
		{"bad uuid", 200, func(s string) string { return strings.Replace(s, "99d9d709-", "99D9D709-", 1) }, "want a value matching <uuid>"},
		{"bad time", 200, func(s string) string {
			return strings.Replace(s, `"created_at":"2022-12-15T02:25:11"`, `"created_at":"2022-12-15T02:25:11Z"`, 1)
		}, "want a value matching <time>"},
		{"placeholder needs a string", 200, func(s string) string { return strings.Replace(s, `"note":""`, `"note":5`, 1) }, "want a value matching <string>"},
		{"object replaced", 200, func(string) string { return `{"vpc":[]}` }, "body.vpc is an array, want an object"},
		{"not json", 200, func(string) string { return `<html>` }, "response body is not JSON"},
	}
	path := write(t, sample)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			problems := Compare(path, tt.status, []byte(tt.mutate(matching)))
			if !strings.Contains(strings.Join(problems, "\n"), tt.wantSub) {
				t.Fatalf("problems %v do not mention %q", problems, tt.wantSub)
			}
		})
	}
}

func TestCompareEmptyBody(t *testing.T) {
	t.Parallel()

	path := write(t, `{"source":"docs","status":204}`)
	if problems := Compare(path, 204, nil); len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if problems := Compare(path, 204, []byte(`{}`)); len(problems) != 1 || problems[0] != "body is not empty" {
		t.Fatalf("problems = %v, want [body is not empty]", problems)
	}
}

func TestCompareRejectsBadGoldenFiles(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		`{"source":"guess","status":200}`:             "unknown source",
		`{"source":"docs","status":200,"extra":true}`: "invalid golden file",
		`not json`: "invalid golden file",
		`{"source":"docs","status":200,"body":"<any>"}`: "",
	}
	for content, wantSub := range tests {
		problems := Compare(write(t, content), 200, []byte(`{"a":1}`))
		if wantSub == "" {
			if len(problems) != 0 {
				t.Errorf("%s: unexpected problems %v", content, problems)
			}
			continue
		}
		if !strings.Contains(strings.Join(problems, "\n"), wantSub) {
			t.Errorf("%s: problems %v do not mention %q", content, problems, wantSub)
		}
	}
	if problems := Compare(filepath.Join(t.TempDir(), "missing.json"), 200, nil); len(problems) != 1 {
		t.Errorf("missing file: problems = %v", problems)
	}
}

func TestPlaceholderKeys(t *testing.T) {
	t.Parallel()

	path := write(t, `{"source": "docs", "status": 200, "body": {"addresses": {"<uuid>": [{"addr": "<string>"}]}, "name": "a"}}`)
	const id = "99d9d709-8478-4b46-9f3f-2206b1023fd3"

	ok := `{"addresses": {"` + id + `": [{"addr": "10.0.0.2"}]}, "name": "a"}`
	if problems := Compare(path, 200, []byte(ok)); len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}

	tests := map[string]string{
		`{"addresses": {}, "name": "a"}`:                                          "body.addresses has no key matching <uuid>",
		`{"addresses": {"not-a-uuid": [{"addr": "x"}]}, "name": "a"}`:             "body.addresses has no key matching <uuid>",
		`{"addresses": {"` + id + `": [{"addr": 5}]}, "name": "a"}`:               "body.addresses." + id + "[0].addr",
		`{"addresses": {"` + id + `": [{"addr": "x"}], "extra": 1}, "name": "a"}`: "body.addresses.extra is not in the real response",
	}
	for body, wantSub := range tests {
		problems := Compare(path, 200, []byte(body))
		if !strings.Contains(strings.Join(problems, "\n"), wantSub) {
			t.Errorf("%s: problems %v do not mention %q", body, problems, wantSub)
		}
	}
}
