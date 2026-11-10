// Package apierr models API errors and renders them in the envelopes
// Huawei Cloud services use. The services do not share one envelope, so
// each service declares its Style and the code/status pairs come from that
// service's error catalogue.
package apierr

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Style selects an error envelope.
type Style int

const (
	// StyleFlat is {"error_code": "VPC.0101", "error_msg": "..."}.
	// Used by VPC, IMS and RDS, and by the API gateway itself.
	StyleFlat Style = iota
	// StyleNested is {"error": {"code": "Ecs.0005", "message": "..."}}.
	// Used by ECS.
	StyleNested
	// StyleXML is the S3-compatible <Error> document used by OBS.
	StyleXML
)

// Codes for conditions that originate in the emulator rather than in an
// emulated service. They are deliberately not Huawei codes, so a user can
// tell an emulator gap from real service behaviour.
const (
	CodeInternal       = "WeiStack.0500"
	CodeNotImplemented = "WeiStack.0501"
)

// Error is an API error with the HTTP status and service error code that
// the client will see.
type Error struct {
	Status  int
	Code    string
	Message string
	cause   error
}

// New builds an Error. The message is formatted like fmt.Sprintf.
func New(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// NotImplemented reports an operation the emulator does not support yet.
// The message names the gap so it is not mistaken for a bug.
func NotImplemented(service, operation string) *Error {
	return New(http.StatusNotImplemented, CodeNotImplemented,
		"weistack does not implement %s %s yet", service, operation)
}

// Internal wraps an unexpected failure. The cause is kept for logs but is
// never sent to the client.
func Internal(cause error) *Error {
	e := New(http.StatusInternalServerError, CodeInternal, "internal error in weistack")
	e.cause = cause
	return e
}

// WithCause returns a copy of e that wraps cause for errors.Is/As and logs.
func (e *Error) WithCause(cause error) *Error {
	c := *e
	c.cause = cause
	return &c
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return e.Code + ": " + e.Message
}

// Unwrap returns the wrapped cause, if any.
func (e *Error) Unwrap() error { return e.cause }

// From converts any error to an *Error. Errors that are not, and do not
// wrap, an *Error become Internal.
func From(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}

type flatBody struct {
	Code    string `json:"error_code"`
	Message string `json:"error_msg"`
}

type nestedBody struct {
	Error nestedDetail `json:"error"`
}

type nestedDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type xmlBody struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
	HostID    string   `xml:"HostId"`
	Resource  string   `xml:"Resource"`
}

// Write renders err in the given style. Callers that want to log the
// error use From(err) to see exactly what was sent. HEAD responses carry
// the status and headers only.
func Write(w http.ResponseWriter, r *http.Request, style Style, err error) {
	e := From(err)

	var (
		body        []byte
		contentType string
		encErr      error
	)
	switch style {
	case StyleNested:
		contentType = "application/json"
		body, encErr = json.Marshal(nestedBody{Error: nestedDetail{Code: e.Code, Message: e.Message}})
	case StyleXML:
		contentType = "application/xml"
		id := reqctx.From(r.Context()).RequestID
		body, encErr = xml.Marshal(xmlBody{
			Code: e.Code, Message: e.Message, RequestID: id, HostID: id, Resource: r.URL.Path,
		})
		body = append([]byte(xml.Header), body...)
	default:
		contentType = "application/json"
		body, encErr = json.Marshal(flatBody{Code: e.Code, Message: e.Message})
	}
	if encErr != nil {
		// Unreachable for these plain string structs; fail closed regardless.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(e.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
