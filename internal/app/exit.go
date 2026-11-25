package app

import "errors"

const (
	exitOK          = 0
	exitInternal    = 1
	exitUsage       = 2
	exitUnreachable = 3
	exitAPI         = 4
	exitData        = 5
)

type exitError struct {
	kind   string
	code   int
	err    error
	status int
	body   []byte
	hint   string
}

func (e *exitError) Error() string { return e.err.Error() }

func (e *exitError) Unwrap() error { return e.err }

func wrapExit(kind string, code int, err error) error {
	if err == nil {
		return nil
	}
	var existing *exitError
	if errors.As(err, &existing) {
		return err
	}
	return &exitError{kind: kind, code: code, err: err}
}

func usageError(err error) error {
	return wrapExit("usage", exitUsage, err)
}

func unreachableError(err error) error {
	return wrapExit("unreachable", exitUnreachable, err)
}

func apiError(status int, body []byte, hint string, err error) error {
	if err == nil {
		return nil
	}
	return &exitError{
		kind:   "api",
		code:   exitAPI,
		status: status,
		body:   body,
		hint:   hint,
		err:    err,
	}
}

func dataError(err error) error {
	return wrapExit("data", exitData, err)
}

// ExitCode returns the CLI exit status for err: 0 when nil, the
// classified code when err wraps an exit error, and 1 otherwise.
func ExitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return exitInternal
}
