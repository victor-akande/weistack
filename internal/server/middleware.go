package server

import (
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// requestIDHeader is the header Huawei Cloud APIs return the request ID in.
const requestIDHeader = "X-Request-Id"

// requestContext assigns the request ID and seeds the per-request info
// that routing, handlers and logging share.
func (s *Server) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := &reqctx.Info{RequestID: s.ids.Hex32(), Region: s.cfg.Region}
		w.Header().Set(requestIDHeader, info.RequestID)
		next.ServeHTTP(w, r.WithContext(reqctx.With(r.Context(), info)))
	})
}

// observe logs every request and feeds the metrics.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		began := time.Now()
		sw := &statusWriter{ResponseWriter: w}

		next.ServeHTTP(sw, r)

		elapsed := time.Since(began)
		info := reqctx.From(r.Context())
		status := sw.statusCode()
		s.metrics.observe(info.Service, r.Method, status, elapsed)

		level := slog.LevelInfo
		switch {
		case status >= http.StatusInternalServerError:
			level = slog.LevelError
		case r.URL.Path == adminPrefix+"/health":
			// Container health probes would otherwise drown the log.
			level = slog.LevelDebug
		}
		s.log.LogAttrs(r.Context(), level, "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("service", info.Service),
			slog.String("operation", info.Operation()),
			slog.String("region", info.Region),
			slog.Int("status", status),
			slog.Int64("bytes", sw.bytes),
			slog.Duration("latency", elapsed),
			slog.String("request_id", info.RequestID),
		)
	})
}

// recoverPanics turns a handler panic into a 500 instead of a dropped
// connection, and logs the stack.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value, compared by identity as net/http does
				panic(rec)
			}
			s.log.ErrorContext(r.Context(), "handler panicked",
				"panic", rec,
				"method", r.Method,
				"path", r.URL.Path,
				"request_id", reqctx.From(r.Context()).RequestID,
				"stack", string(debug.Stack()),
			)
			if sw, ok := w.(*statusWriter); ok && sw.wrote {
				return // too late to send an error body
			}
			apierr.Write(w, r, apierr.StyleFlat, apierr.Internal(nil))
		}()
		next.ServeHTTP(w, r)
	})
}

// corsExposed lists response headers browser clients may read.
var corsExposed = strings.Join([]string{
	requestIDHeader, "ETag", "Content-Length", "Content-Range", "Last-Modified",
	"X-Obs-Request-Id", "X-Obs-Id-2", "X-Amz-Request-Id",
}, ", ")

// cors lets browser-based tools (and a future dashboard) call the
// emulator. It is wide open on purpose: the emulator holds no real data
// and accepts any credentials anyway.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", corsExposed)
		h.Add("Vary", "Origin")

		// Only a genuine preflight is answered here; a plain OPTIONS
		// request still reaches the service (OBS has an OPTIONS API).
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			h.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
			if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
				h.Set("Access-Control-Allow-Headers", req)
			}
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// statusWriter records the status and size of a response.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// ReadFrom keeps the underlying writer's fast path (sendfile) available
// when a handler streams a file with io.Copy.
func (w *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	n, err := io.Copy(w.ResponseWriter, src)
	w.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach Flush, Hijack and deadlines.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) statusCode() int {
	if !w.wrote {
		return http.StatusOK
	}
	return w.status
}
