// Package httpx holds the small JSON helpers every handler needs.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Errors returned by DecodeJSON. Services map them to their own codes.
var (
	// ErrBodyTooLarge means the body exceeded the server's size limit.
	ErrBodyTooLarge = errors.New("request body too large")
	// ErrMalformedJSON means the body is not one well-formed JSON value
	// of the expected shape.
	ErrMalformedJSON = errors.New("malformed JSON body")
	// ErrEmptyBody means a body was required but none was sent.
	ErrEmptyBody = errors.New("request body is empty")
)

// DecodeJSON reads exactly one JSON value from the request body into dst.
// Unknown fields are ignored, as the real APIs do.
func DecodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			return fmt.Errorf("%w: limit is %d bytes", ErrBodyTooLarge, tooLarge.Limit)
		case errors.Is(err, io.EOF):
			return ErrEmptyBody
		default:
			return fmt.Errorf("%w: %s", ErrMalformedJSON, err.Error())
		}
	}
	// Reject trailing content such as a second JSON document.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: unexpected data after the JSON value", ErrMalformedJSON)
	}
	return nil
}

// WriteJSON sends v as a JSON response with the given status. The body is
// encoded before any header is written, so an encoding failure can still
// become a clean error response in the caller.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encoding response: %w", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return nil
}
