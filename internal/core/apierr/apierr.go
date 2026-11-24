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
	// StyleCodeMessage is {"code": "VPC.0101", "message": "..."}.
	// Used by the VPC v1 API (VPCs, subnets).
	StyleCodeMessage
	// StyleFlatRequestID is StyleFlat with a leading "request_id" field.
	// Used by the VPC v3 API (security groups).
	StyleFlatRequestID
	// StyleNestedFlat is {"error": {"error_code": "KMS.0207",
	// "error_msg": "..."}}. Used by KMS.
	StyleNestedFlat
)

// Codes for conditions that originate in the emulator rather than in an
// emulated service. They are deliberately not Huawei codes, so a user can
// tell an emulator gap from real service behaviour.
const (
	CodeInternal       = "WeiStack.0500"
	CodeNotImplemented = "WeiStack.0501"
	CodeDataFull       = "WeiStack.0507"
)

// ErrDataFull refuses a write once WeiStack's data has reached
// -max-data-bytes (internal/core/budget). Internal passes it through, so
// every service answers it as it is.
var ErrDataFull = New(http.StatusInsufficientStorage, CodeDataFull,
	"WeiStack's data has reached its limit (-max-data-bytes): delete resources or objects, or start WeiStack with a higher limit").
	WithHint("delete resources or objects, or restart with a higher -max-data-bytes (0 is no limit); changes and deletes still work")

// Error is an API error with the HTTP status and service error code that
// the client will see.
type Error struct {
	Status  int
	Code    string
	Message string
	// AuthorizationMessage is the encoded explanation of a permission
	// denial, sent as the top-level encoded_authorization_message field
	// that Huawei documents for denials (api-iam5 ErrorCode) and the SDKs
	// parse. It is not part of the XML envelope.
	AuthorizationMessage string
	// Hint says what to do about the error, for people and agents. It is
	// sent in the HintHeader response header, never in the body, so the
	// body stays exactly as Huawei Cloud sends it.
	Hint  string
	cause error
}

// HintHeader carries an error's Hint.
const HintHeader = "X-WeiStack-Hint"

// maxHint bounds a hint, so a header stays small.
const maxHint = 512

// New builds an Error. The message is formatted like fmt.Sprintf.
func New(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// NotImplemented reports an operation the emulator does not support yet.
// The message names the gap so it is not mistaken for a bug.
func NotImplemented(service, operation string) *Error {
	return New(http.StatusNotImplemented, CodeNotImplemented,
		"weistack does not implement %s %s yet", service, operation).
		WithHint("docs/coverage.md lists every operation WeiStack serves; ask for this one in an issue")
}

// Internal wraps an unexpected failure. The cause is kept for logs but is
// never sent to the client.
func Internal(cause error) *Error {
	if errors.Is(cause, ErrDataFull) {
		return ErrDataFull
	}
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

// WithAuthorizationMessage returns a copy of e that carries an encoded
// authorization message.
func (e *Error) WithAuthorizationMessage(m string) *Error {
	c := *e
	c.AuthorizationMessage = m
	return &c
}

// WithHint returns a copy of e that carries a hint.
func (e *Error) WithHint(hint string) *Error {
	c := *e
	c.Hint = hint
	return &c
}

// headerSafe makes s a single-line header value of printable ASCII, at
// most maxHint bytes.
func headerSafe(s string) string {
	b := make([]byte, 0, min(len(s), maxHint))
	for i := 0; i < len(s) && len(b) < maxHint; i++ {
		switch c := s[i]; {
		case c == '\t' || c == '\n' || c == '\r':
			b = append(b, ' ')
		case c >= 0x20 && c < 0x7f:
			b = append(b, c)
		}
	}
	return string(b)
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
	Code          string `json:"error_code"`
	Message       string `json:"error_msg"`
	Authorization string `json:"encoded_authorization_message,omitempty"`
}

type codeMessageBody struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	Authorization string `json:"encoded_authorization_message,omitempty"`
}

type flatRequestIDBody struct {
	RequestID     string `json:"request_id"`
	Code          string `json:"error_code"`
	Message       string `json:"error_msg"`
	Authorization string `json:"encoded_authorization_message,omitempty"`
}

type nestedBody struct {
	Error         nestedDetail `json:"error"`
	Authorization string       `json:"encoded_authorization_message,omitempty"`
}

type nestedDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type nestedFlatBody struct {
	Error         flatDetail `json:"error"`
	Authorization string     `json:"encoded_authorization_message,omitempty"`
}

type flatDetail struct {
	Code    string `json:"error_code"`
	Message string `json:"error_msg"`
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
		body, encErr = json.Marshal(nestedBody{
			Error: nestedDetail{Code: e.Code, Message: e.Message}, Authorization: e.AuthorizationMessage,
		})
	case StyleNestedFlat:
		contentType = "application/json"
		body, encErr = json.Marshal(nestedFlatBody{
			Error: flatDetail{Code: e.Code, Message: e.Message}, Authorization: e.AuthorizationMessage,
		})
	case StyleXML:
		contentType = "application/xml"
		id := reqctx.From(r.Context()).RequestID
		body, encErr = xml.Marshal(xmlBody{
			Code: e.Code, Message: e.Message, RequestID: id, HostID: id, Resource: r.URL.Path,
		})
		body = append([]byte(xml.Header), body...)
	case StyleCodeMessage:
		contentType = "application/json"
		body, encErr = json.Marshal(codeMessageBody{Code: e.Code, Message: e.Message, Authorization: e.AuthorizationMessage})
	case StyleFlatRequestID:
		contentType = "application/json"
		body, encErr = json.Marshal(flatRequestIDBody{
			RequestID: reqctx.From(r.Context()).RequestID, Code: e.Code, Message: e.Message,
			Authorization: e.AuthorizationMessage,
		})
	default:
		contentType = "application/json"
		body, encErr = json.Marshal(flatBody{Code: e.Code, Message: e.Message, Authorization: e.AuthorizationMessage})
	}
	if encErr != nil {
		// Unreachable for these plain string structs; fail closed regardless.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h := headerSafe(e.Hint); h != "" {
		w.Header().Set(HintHeader, h)
	}
	w.WriteHeader(e.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
