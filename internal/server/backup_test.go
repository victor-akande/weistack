package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

type fakeBackups struct{ resetErr error }

func (fakeBackups) Write(_ context.Context, w io.Writer) error {
	_, err := io.WriteString(w, "archive")
	return err
}

func (b fakeBackups) BeforeReset(context.Context) (string, error) {
	return "/data/backups/r", b.resetErr
}

func newBackupServer(t *testing.T, b Backups) (*Server, store.Store) {
	t.Helper()
	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Options{
		Config: cfg, ProjectID: testProject, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Store: st, Engine: lifecycle.New(lifecycle.Options{}), IDs: ids.NewSeeded(1), Backups: b,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func TestBackupRoute(t *testing.T) {
	t.Parallel()
	srv, _ := newBackupServer(t, fakeBackups{})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, request(http.MethodGet, "http://localhost/_weistack/backup", ""))
	if w.Code != http.StatusOK || w.Body.String() != "archive" || w.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("GET /_weistack/backup = %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	// Never from another machine, even with the administrator's keys.
	w = httptest.NewRecorder()
	r := request(http.MethodGet, "http://localhost/_weistack/backup", "")
	srv.NetworkHandler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("network GET /_weistack/backup = %d", w.Code)
	}
	// Without persistence there is nothing to back up.
	plain, _ := newBackupServer(t, nil)
	w = httptest.NewRecorder()
	plain.Handler().ServeHTTP(w, request(http.MethodGet, "http://localhost/_weistack/backup", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /_weistack/backup without -persist = %d", w.Code)
	}
}

func TestResetRefusedWithoutABackup(t *testing.T) {
	t.Parallel()
	srv, st := newBackupServer(t, fakeBackups{resetErr: errors.New("disk full")})
	scope := store.Scope{Region: "r", ProjectID: "p", Kind: "k"}
	if _, err := st.Put(context.Background(), scope, "kept", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, request(http.MethodPost, "http://localhost/_weistack/reset", ""))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("reset = %d %s", w.Code, w.Body.String())
	}
	if _, err := st.Get(context.Background(), scope, "kept"); err != nil {
		t.Fatalf("the reset wiped data it could not back up: %v", err)
	}
}
