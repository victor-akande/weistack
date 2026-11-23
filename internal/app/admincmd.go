package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

const adminUsage = "usage: weistack admin METHOD PATH [BODY] [flags]\n" +
	"  for example: weistack admin POST reset, or weistack admin POST accounts '{\"name\":\"partner\"}'"

// adminCommand calls the admin API of a running WeiStack, signed with the
// administrator's keys, as -iam=enforce requires: weistack admin METHOD
// PATH [BODY], then the flags the server was started with. A PATH without
// a leading slash is under /_weistack. The response body goes to stdout.
func adminCommand(ctx context.Context, env Env) error {
	args := env.Args[1:]
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		return errors.New(adminUsage)
	}
	method, path, args := strings.ToUpper(args[0]), args[1], args[2:]
	var body string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		body, args = args[0], args[1:]
	}
	if !strings.HasPrefix(path, "/") {
		path = adminPrefixPath + "/" + path
	}
	cfg, err := config.Load(args, env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	creds, _, err := loadAdmin(cfg, slog.New(slog.NewTextHandler(env.Stderr, nil)))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort(clientHost(cfg), strconv.Itoa(cfg.Port)) + path
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	sigcheck.SignSDKHMAC(req, creds.AccessKey, creds.SecretKey, req.URL.Path, []byte(body), time.Now())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, 1<<30))
	if err != nil {
		return fmt.Errorf("admin: reading the response: %w", err)
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("admin: %s %s returned %s: %s", method, path, res.Status, bytes.TrimSpace(out))
	}
	_, err = env.Stdout.Write(out)
	return err
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
