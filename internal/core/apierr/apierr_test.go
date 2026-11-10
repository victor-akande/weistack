package apierr

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/reqctx"
)

func TestWriteStyles(t *testing.T) {
	t.Parallel()

	const reqID = "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name        string
		style       Style
		err         error
		wantStatus  int
		wantType    string
		wantBody    string
		forbidInOut string
	}{
		{
			name:       "flat",
			style:      StyleFlat,
			err:        New(http.StatusNotFound, "VPC.0202", "vpc %s not found", "abc"),
			wantStatus: http.StatusNotFound,
			wantType:   "application/json",
			wantBody:   `{"error_code":"VPC.0202","error_msg":"vpc abc not found"}`,
		},
		{
			name:       "nested",
			style:      StyleNested,
			err:        New(http.StatusBadRequest, "Ecs.0005", "bad request"),
			wantStatus: http.StatusBadRequest,
			wantType:   "application/json",
			wantBody:   `{"error":{"code":"Ecs.0005","message":"bad request"}}`,
		},
		{
			name:       "xml",
			style:      StyleXML,
			err:        New(http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist"),
			wantStatus: http.StatusNotFound,
			wantType:   "application/xml",
			wantBody: `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
				`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>` +
				`<RequestId>` + reqID + `</RequestId><HostId>` + reqID + `</HostId><Resource>/photos/cat.png</Resource></Error>`,
		},
		{
			name:       "code and message",
			style:      StyleCodeMessage,
			err:        New(http.StatusConflict, "VPC.0104", "vpc has subnets"),
			wantStatus: http.StatusConflict,
			wantType:   "application/json",
			wantBody:   `{"code":"VPC.0104","message":"vpc has subnets"}`,
		},
		{
			name:       "flat with request id",
			style:      StyleFlatRequestID,
			err:        New(http.StatusNotFound, "VPC.9904", "security group not found"),
			wantStatus: http.StatusNotFound,
			wantType:   "application/json",
			wantBody:   `{"request_id":"` + reqID + `","error_code":"VPC.9904","error_msg":"security group not found"}`,
		},
		{
			name:       "wrapped api error keeps its code",
			style:      StyleFlat,
			err:        fmt.Errorf("creating subnet: %w", New(http.StatusConflict, "VPC.0208", "cidr overlaps")),
			wantStatus: http.StatusConflict,
			wantType:   "application/json",
			wantBody:   `{"error_code":"VPC.0208","error_msg":"cidr overlaps"}`,
		},
		{
			name:        "unknown errors become internal and do not leak",
			style:       StyleFlat,
			err:         errors.New("open /data/weistack.db: permission denied"),
			wantStatus:  http.StatusInternalServerError,
			wantType:    "application/json",
			wantBody:    `{"error_code":"WeiStack.0500","error_msg":"internal error in weistack"}`,
			forbidInOut: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/photos/cat.png", nil)
			r = r.WithContext(reqctx.With(r.Context(), &reqctx.Info{RequestID: reqID}))
			w := httptest.NewRecorder()

			Write(w, r, tt.style, tt.err)

			res := w.Result()
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)

			if res.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if got := res.Header.Get("Content-Type"); got != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if string(body) != tt.wantBody {
				t.Errorf("body mismatch\n got: %s\nwant: %s", body, tt.wantBody)
			}
			if tt.forbidInOut != "" && strings.Contains(string(body), tt.forbidInOut) {
				t.Errorf("body leaks internal detail %q", tt.forbidInOut)
			}
		})
	}
}

func TestWriteHeadHasNoBody(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodHead, "/bucket", nil)
	w := httptest.NewRecorder()

	Write(w, r, StyleXML, New(http.StatusNotFound, "NoSuchBucket", "missing"))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD response has a body: %q", w.Body.String())
	}
}

func TestNotImplementedNamesTheGap(t *testing.T) {
	t.Parallel()

	e := NotImplemented("ecs", "AttachServerVolume")
	if e.Status != http.StatusNotImplemented || e.Code != CodeNotImplemented {
		t.Fatalf("got status %d code %q", e.Status, e.Code)
	}
	for _, sub := range []string{"ecs", "AttachServerVolume", "not implement"} {
		if !strings.Contains(e.Message, sub) {
			t.Errorf("message %q does not mention %q", e.Message, sub)
		}
	}
}

func TestCauseAndUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("disk full")
	base := New(http.StatusInternalServerError, "RDS.0001", "backup failed")
	wrapped := base.WithCause(cause)

	if !errors.Is(wrapped, cause) {
		t.Error("errors.Is does not find the cause")
	}
	if base.Unwrap() != nil {
		t.Error("WithCause mutated the original error")
	}
	if got, want := wrapped.Error(), "RDS.0001: backup failed: disk full"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got, want := base.Error(), "RDS.0001: backup failed"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	internal := From(cause)
	if internal.Code != CodeInternal || !errors.Is(internal, cause) {
		t.Errorf("From(plain error) = %v, want internal error wrapping the cause", internal)
	}
	if From(wrapped) != wrapped {
		t.Error("From should return an existing *Error unchanged")
	}
}
