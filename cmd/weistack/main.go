// Command weistack runs a local emulator of core Huawei Cloud services.
//
// Usage:
//
//	weistack [flags]              run the emulator
//	weistack version [flags]      print the version
//	weistack healthcheck [flags]  exit 0 if a running emulator is healthy
//	weistack ca [flags]           print the local CA certificate
//	weistack credentials [flags]  print the administrator's keys as shell exports
//	weistack admin METHOD PATH [BODY] [flags]
//	                              call the admin API, signed as the administrator
//	weistack backup [FILE] [flags]
//	                              archive the data directory, running or not
//	weistack restore FILE [flags] unpack an archive into an empty data directory
//	weistack -h                   list flags
//
// Every subcommand accepts -output json (or WEISTACK_OUTPUT=json) for
// machine-readable output.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/victor-akande/weistack/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal starts a graceful shutdown, restore default
	// handling so a second Ctrl-C terminates immediately.
	go func() {
		<-ctx.Done()
		stop()
	}()

	code := app.Main(ctx, app.Env{
		Args:   os.Args[1:],
		Getenv: os.Getenv,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	stop()
	os.Exit(code)
}
