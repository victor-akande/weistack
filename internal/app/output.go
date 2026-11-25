package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/victor-akande/weistack/internal/core/config"
)

func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	if w == nil {
		return nil
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func detectOutputMode(args []string, getenv func(string) string) string {
	var candidate string
	if getenv != nil {
		candidate = getenv(config.EnvPrefix + "OUTPUT")
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if arg == "-output" || arg == "--output" {
			if i+1 < len(args) {
				candidate = args[i+1]
				i++
			}
			continue
		}
		if v, ok := strings.CutPrefix(arg, "-output="); ok {
			candidate = v
			continue
		}
		if v, ok := strings.CutPrefix(arg, "--output="); ok {
			candidate = v
		}
	}
	if strings.ToLower(strings.TrimSpace(candidate)) == config.OutputJSON {
		return config.OutputJSON
	}
	return config.OutputText
}

func loadConfig(args []string, env Env) (config.Config, bool, error) {
	var buf bytes.Buffer
	cfg, err := config.Load(args, env.Getenv, &buf)
	if errors.Is(err, flag.ErrHelp) {
		if env.Stderr != nil {
			_, _ = env.Stderr.Write(buf.Bytes())
		}
		return config.Config{}, true, nil
	}
	if err != nil {
		if detectOutputMode(env.Args, env.Getenv) != config.OutputJSON && env.Stderr != nil {
			_, _ = env.Stderr.Write(buf.Bytes())
		}
		return config.Config{}, false, usageError(err)
	}
	return cfg, false, nil
}

type jsonErrorEnvelope struct {
	Error jsonErrorDetail `json:"error"`
}

type jsonErrorDetail struct {
	Kind     string           `json:"kind"`
	ExitCode int              `json:"exit_code"`
	Message  string           `json:"message"`
	Status   *int             `json:"status,omitempty"`
	Response *json.RawMessage `json:"response,omitempty"`
	Hint     string           `json:"hint,omitempty"`
}

func apiResponseJSON(body []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && json.Valid(trimmed) {
		var compact bytes.Buffer
		if err := json.Compact(&compact, trimmed); err == nil {
			return json.RawMessage(compact.Bytes())
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(string(body))
	return json.RawMessage(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// Main runs the CLI, writes any error to env.Stderr in the selected
// output format, and returns the process exit code.
func Main(ctx context.Context, env Env) int {
	err := Run(ctx, env)
	if err == nil {
		return exitOK
	}

	code := ExitCode(err)
	kind := "internal"
	var ee *exitError
	if errors.As(err, &ee) {
		kind = ee.kind
	}

	if detectOutputMode(env.Args, env.Getenv) == config.OutputJSON {
		detail := jsonErrorDetail{
			Kind:     kind,
			ExitCode: code,
			Message:  err.Error(),
		}
		if ee != nil {
			detail.Hint = ee.hint
			if kind == "api" {
				status := ee.status
				resp := apiResponseJSON(ee.body)
				detail.Status = &status
				detail.Response = &resp
			}
		}
		_ = writeJSON(env.Stderr, jsonErrorEnvelope{Error: detail})
		return code
	}

	if env.Stderr != nil {
		fmt.Fprintln(env.Stderr, "weistack:", err)
		if ee != nil && ee.hint != "" {
			fmt.Fprintln(env.Stderr, "hint:", ee.hint)
		}
	}
	return code
}
