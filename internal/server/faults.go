package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/faults"
	"github.com/victor-akande/weistack/internal/core/httpx"
)

// Fault injection: /_weistack/faults adds, lists and removes the
// failures of package faults. Request faults are applied here, before a
// request reaches its service or its credentials are checked, where API
// Gateway throttles.

// The errors request faults answer with when the rule names no code:
// API Gateway's documented throttling error (APIGW.0308, 429) for the
// services behind it, OBS's SlowDown (503) for OBS, and WeiStack's own
// code for other statuses.
var (
	errThrottled = apierr.New(http.StatusTooManyRequests, "APIGW.0308", "The throttling threshold has been reached.")
	errSlowDown  = apierr.New(http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
)

// injectFault applies a request fault to r, if one matches. It reports
// whether it answered the request.
func (s *Server) injectFault(m *mounted, w http.ResponseWriter, r *http.Request) bool {
	if s.faults == nil {
		return false
	}
	name := m.svc.Name()
	rule, ok := s.faults.Request(name, r.Method, r.URL.Path)
	if !ok {
		return false
	}
	s.log.InfoContext(r.Context(), "fault injected", "fault", rule.ID, "service", name, "status", rule.Status, "delay_ms", rule.DelayMS)
	if d := rule.Delay(); d > 0 {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
			return true
		}
	}
	if rule.Status == 0 {
		return false // a delay only
	}
	style := apierr.StyleFlatRequestID
	if name == "obs" {
		style = apierr.StyleXML
	}
	apierr.Write(w, r, style, faultError(name, rule))
	return true
}

func faultError(service string, r faults.Rule) *apierr.Error {
	return injectedError(service, r).WithHint("injected by WeiStack fault rule " + r.ID +
		": list the rules with weistack admin GET faults, clear them with weistack admin DELETE faults")
}

func injectedError(service string, r faults.Rule) *apierr.Error {
	if r.Code == "" {
		switch {
		case service == "obs" && r.Status == http.StatusServiceUnavailable:
			return errSlowDown
		case service != "obs" && r.Status == http.StatusTooManyRequests:
			return errThrottled
		}
	}
	code, msg := r.Code, r.Message
	if code == "" {
		code = "WeiStack." + pad(r.Status)
	}
	if msg == "" {
		msg = "Injected fault " + r.ID + "."
	}
	return apierr.New(r.Status, code, "%s", msg)
}

// pad writes a status as WeiStack's four-digit codes do: 503 is 0503.
func pad(status int) string { return fmt.Sprintf("%04d", status) }

var errFaultBody = apierr.New(http.StatusBadRequest, "WeiStack.0400", "the body must be a JSON fault rule")

// maxFaultBody bounds the body of POST /_weistack/faults.
const maxFaultBody = 4 << 10

func (s *Server) handleAddFault(w http.ResponseWriter, r *http.Request) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxFaultBody))
	if err != nil {
		return errFaultBody
	}
	var rule faults.Rule
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rule); err != nil || dec.More() {
		return errFaultBody
	}
	// A rule applies once unless times says otherwise (0: until removed).
	var given struct {
		Times *int `json:"times"`
	}
	if json.Unmarshal(raw, &given) == nil && given.Times == nil {
		rule.Times = 1
	}
	if rule.ID != "" || rule.Remaining != 0 || rule.Hits != 0 || !rule.Created.IsZero() {
		return apierr.New(http.StatusBadRequest, "WeiStack.0400", "id, remaining, hits and created are set by WeiStack")
	}
	if rule.Type == faults.TypeRequest && rule.Service != "" && !slices.Contains(s.names, rule.Service) {
		return apierr.New(http.StatusBadRequest, "WeiStack.0400", "%s is not an enabled service", rule.Service)
	}
	added, err := s.faults.Add(rule)
	if errors.Is(err, faults.ErrInvalid) {
		return apierr.New(http.StatusBadRequest, "WeiStack.0400", "%s", err)
	}
	if err != nil {
		return apierr.Internal(err)
	}
	s.log.InfoContext(r.Context(), "fault added", "fault", added.ID, "type", added.Type)
	return httpx.WriteJSON(w, http.StatusCreated, struct {
		Fault faults.Rule `json:"fault"`
	}{added})
}

func (s *Server) handleListFaults(w http.ResponseWriter, _ *http.Request) error {
	return httpx.WriteJSON(w, http.StatusOK, struct {
		Faults []faults.Rule `json:"faults"`
	}{s.faults.List()})
}

func (s *Server) handleClearFaults(w http.ResponseWriter, _ *http.Request) error {
	s.faults.Clear()
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleRemoveFault(w http.ResponseWriter, r *http.Request) error {
	if !s.faults.Remove(chi.URLParam(r, "id")) {
		return apierr.New(http.StatusNotFound, "WeiStack.0404", "no fault %s", chi.URLParam(r, "id"))
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
