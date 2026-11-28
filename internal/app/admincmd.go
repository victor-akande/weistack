package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

const adminUsage = "usage: weistack admin METHOD PATH [BODY] [flags]\n" +
	"  for example: weistack admin POST reset, or weistack admin POST accounts '{\"name\":\"partner\"}'"

// adminCommand calls the admin API of a running WeiStack, signed with the
// administrator's keys, as -iam=enforce requires: weistack admin METHOD
// PATH [BODY] and the flags the server was started with, in any order.
// A PATH without a leading slash is under /_weistack. The response body goes to stdout.
func adminCommand(ctx context.Context, env Env) error {
	args := env.Args[1:]
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		if env.Stderr != nil {
			fmt.Fprintln(env.Stderr, adminUsage)
		}
		return nil
	}
	cfg, rest, help, err := loadConfigArgs(args, env)
	if help {
		return nil
	}
	if err != nil {
		return err
	}
	if len(rest) < 2 || len(rest) > 3 {
		return usageError(errors.New(adminUsage))
	}
	method, path := strings.ToUpper(rest[0]), rest[1]
	var body string
	if len(rest) == 3 {
		body = rest[2]
	}
	if !strings.HasPrefix(path, "/") {
		path = adminPrefixPath + "/" + path
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := adminRequest(ctx, cfg, env, method, path, body)
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 1<<30))
	if err != nil {
		return fmt.Errorf("admin: reading the response: %w", err)
	}
	if res.StatusCode/100 != 2 {
		return apiError(res.StatusCode, out, res.Header.Get(apierr.HintHeader),
			fmt.Errorf("admin: %s %s returned %s: %s", method, path, res.Status, bytes.TrimSpace(out)))
	}
	_, err = env.Stdout.Write(out)
	return err
}

// adminRequest sends a request to the admin API of the WeiStack cfg
// describes, signed with the administrator's keys.
func adminRequest(ctx context.Context, cfg config.Config, env Env, method, path, body string) (*http.Response, error) {
	creds, _, err := loadAdmin(cfg, slog.New(slog.NewTextHandler(env.Stderr, nil)))
	if err != nil {
		return nil, err
	}
	url := "http://" + net.JoinHostPort(clientHost(cfg), strconv.Itoa(cfg.Port)) + path
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	sigcheck.SignSDKHMAC(req, creds.AccessKey, creds.SecretKey, req.URL.Path, []byte(body), time.Now())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, unreachableError(err)
	}
	return res, nil
}

// adminPrefixPath is the root of the admin API.
const adminPrefixPath = "/_weistack"

// clientHost is the address a client on this machine reaches the server
// at: a wildcard bind is reached through loopback.
func clientHost(cfg config.Config) string {
	host := cfg.Host
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		return "127.0.0.1"
	}
	return host
}
