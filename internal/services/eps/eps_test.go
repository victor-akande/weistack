package eps

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func list(t *testing.T, query string) (int, []map[string]any) {
	t.Helper()
	svc, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), time.Date(2026, 11, 14, 8, 0, 0, 5, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	svc.Routes(r)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1.0/enterprise-projects"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		EnterpriseProjects []map[string]any `json:"enterprise_projects"`
		TotalCount         int              `json:"total_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.TotalCount, out.EnterpriseProjects
}

func TestListTheDefaultEnterpriseProject(t *testing.T) {
	t.Parallel()
	total, eps := list(t, "")
	if total != 1 || len(eps) != 1 {
		t.Fatalf("total %d, %v", total, eps)
	}
	ep := eps[0]
	if ep["id"] != "0" || ep["name"] != "default" || ep["status"] != float64(1) || ep["type"] != "prod" ||
		ep["delete_flag"] != false || ep["created_at"] != "2026-11-14T08:00:00Z" {
		t.Fatalf("default = %v", ep)
	}

	for query, want := range map[string]int{
		"?id=0": 1, "?name=def": 1, "?status=1": 1, "?type=prod": 1, "?limit=1": 1, "?limit=0": 1,
		"?id=other": 0, "?name=prod": 0, "?status=2": 0, "?type=poc": 0, "?offset=1": 0,
	} {
		if _, got := list(t, query); len(got) != want {
			t.Errorf("%s: %d projects, want %d", query, len(got), want)
		}
	}
}
