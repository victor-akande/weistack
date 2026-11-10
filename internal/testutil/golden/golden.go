// Package golden compares HTTP responses with golden files that record
// what real Huawei Cloud returns.
//
// A golden file is JSON:
//
//	{
//	  "source": "docs",          // how much to trust it, see Sources
//	  "status": 200,
//	  "body": { ... }            // omitted for an empty body
//	}
//
// The response must have exactly the golden body's fields, with the same
// JSON types, at every depth. Values must match too, except where the
// golden value is a placeholder for something that legitimately varies:
//
//	"<uuid>"     lowercase UUID
//	"<hex32>"    32 lowercase hex characters
//	"<time>"     2006-01-02T15:04:05   (VPC v1 style, UTC, no zone)
//	"<time-z>"   2006-01-02T15:04:05Z
//	"<string>"   any string
//	"<any>"      anything, including null
package golden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Sources a golden file may declare, from least to most trusted.
var Sources = map[string]bool{
	"sdk-model": true, // field names and types from the official SDK models
	"fixture":   true, // sample from an open-source test fixture
	"docs":      true, // example in the API reference
	"recorded":  true, // captured from real Huawei Cloud
}

type file struct {
	Source string          `json:"source"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

var placeholders = map[string]*regexp.Regexp{
	"<uuid>":   regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"<hex32>":  regexp.MustCompile(`^[0-9a-f]{32}$`),
	"<time>":   regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`),
	"<time-z>": regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`),
	"<string>": regexp.MustCompile(`(?s)^.*$`),
}

// Assert fails the test unless status and body match the golden file.
func Assert(t *testing.T, path string, status int, body []byte) {
	t.Helper()
	for _, problem := range Compare(path, status, body) {
		t.Errorf("%s: %s", path, problem)
	}
	if t.Failed() {
		t.Logf("response body: %s", body)
	}
}

// Compare returns every difference between the response and the golden
// file, or nil when they match.
func Compare(path string, status int, body []byte) []string {
	raw, err := os.ReadFile(path) //nolint:gosec // test data path chosen by the test
	if err != nil {
		return []string{err.Error()}
	}
	var g file
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return []string{"invalid golden file: " + err.Error()}
	}
	if !Sources[g.Source] {
		return []string{fmt.Sprintf("golden file has unknown source %q", g.Source)}
	}

	var problems []string
	if status != g.Status {
		problems = append(problems, fmt.Sprintf("status = %d, want %d", status, g.Status))
	}

	if len(g.Body) == 0 {
		if len(bytes.TrimSpace(body)) != 0 {
			problems = append(problems, "body is not empty")
		}
		return problems
	}

	var want, got any
	if err := json.Unmarshal(g.Body, &want); err != nil {
		return append(problems, "invalid golden body: "+err.Error())
	}
	if err := json.Unmarshal(body, &got); err != nil {
		return append(problems, "response body is not JSON: "+err.Error())
	}
	return append(problems, diff("body", want, got)...)
}

func diff(path string, want, got any) []string {
	if s, ok := want.(string); ok {
		if s == "<any>" {
			return nil
		}
		if re, ok := placeholders[s]; ok {
			gs, isString := got.(string)
			if !isString || !re.MatchString(gs) {
				return []string{fmt.Sprintf("%s = %s, want a value matching %s", path, show(got), s)}
			}
			return nil
		}
	}

	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s is %s, want an object", path, kind(got))}
		}
		var out []string
		for _, k := range sortedKeys(w) {
			gv, present := g[k]
			if !present {
				out = append(out, fmt.Sprintf("%s.%s is missing", path, k))
				continue
			}
			out = append(out, diff(path+"."+k, w[k], gv)...)
		}
		for _, k := range sortedKeys(g) {
			if _, expected := w[k]; !expected {
				out = append(out, fmt.Sprintf("%s.%s is not in the real response (value %s)", path, k, show(g[k])))
			}
		}
		return out
	case []any:
		g, ok := got.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s is %s, want an array", path, kind(got))}
		}
		if len(g) != len(w) {
			return []string{fmt.Sprintf("%s has %d elements, want %d", path, len(g), len(w))}
		}
		var out []string
		for i := range w {
			out = append(out, diff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i])...)
		}
		return out
	default:
		if kind(want) != kind(got) {
			return []string{fmt.Sprintf("%s is %s, want %s", path, kind(got), kind(want))}
		}
		if want != got {
			return []string{fmt.Sprintf("%s = %s, want %s", path, show(got), show(want))}
		}
		return nil
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func kind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	s := string(b)
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return strings.TrimSpace(s)
}
