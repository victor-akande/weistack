package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type payload struct {
	Name string `json:"name"`
	Size int    `json:"size"`
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		limit   int64
		want    payload
		wantErr error
	}{
		{name: "valid", body: `{"name":"vpc-a","size":3}`, want: payload{"vpc-a", 3}},
		{name: "unknown fields are ignored", body: `{"name":"x","extra":true}`, want: payload{Name: "x"}},
		{name: "trailing whitespace is fine", body: `{"name":"x"}` + "\n  ", want: payload{Name: "x"}},
		{name: "empty body", body: ``, wantErr: ErrEmptyBody},
		{name: "syntax error", body: `{"name":`, wantErr: ErrMalformedJSON},
		{name: "wrong type", body: `{"size":"big"}`, wantErr: ErrMalformedJSON},
		{name: "two documents", body: `{"name":"x"}{"name":"y"}`, wantErr: ErrMalformedJSON},
		{name: "over the limit", body: `{"name":"` + strings.Repeat("a", 200) + `"}`, limit: 64, wantErr: ErrBodyTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			if tt.limit > 0 {
				r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, tt.limit)
			}
			var got payload
			err := DecodeJSON(r, &got)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("decoded %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	if err := WriteJSON(w, http.StatusCreated, payload{"a", 1}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got, want := w.Body.String(), `{"name":"a","size":1}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestWriteJSONEncodingFailureWritesNothing(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	if err := WriteJSON(w, http.StatusOK, make(chan int)); err == nil {
		t.Fatal("WriteJSON of an unencodable value succeeded")
	}
	if w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Fatalf("a failed WriteJSON touched the response: headers %v body %q", w.Header(), w.Body.String())
	}
}

func FuzzDecodeJSON(f *testing.F) {
	f.Add(`{"name":"a","size":1}`)
	f.Add(`[1,2`)
	f.Add(`{"size":1e999}`)
	f.Fuzz(func(_ *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var p payload
		// Must never panic, whatever the input.
		_ = DecodeJSON(r, &p)
	})
}
