// Command weistack runs a local emulator of core Huawei Cloud services.
//
// Usage:
//
//	weistack [flags]              run the emulator
//	weistack version              print the version
//	weistack healthcheck [flags]  exit 0 if a running emulator is healthy
//	weistack -h                   list flags
package main

import (
	"context"
	"fmt"
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

	err := app.Run(ctx, app.Env{
		Args:   os.Args[1:],
		Getenv: os.Getenv,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "weistack:", err)
		os.Exit(1)
	}
}
