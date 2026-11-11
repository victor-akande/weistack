// Package app wires the emulator together and runs it. It is separate
// from package main so the whole program can be driven from tests.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/ecs"
	"github.com/victor-akande/weistack/internal/services/ims"
	"github.com/victor-akande/weistack/internal/services/obs"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/version"
)

const (
	databaseFile  = "weistack.db"
	projectIDFile = "project_id"
	objectsDir    = "objects"
)

// Env is the process environment the app runs in, injected for tests.
type Env struct {
	Args   []string // without the program name
	Getenv func(string) string
	Stdout io.Writer
	Stderr io.Writer
	// OnReady, if set, is called with the bound address once the server
	// is accepting connections.
	OnReady func(addr net.Addr)
}

// Run executes the command line and blocks until the server stops. It
// returns nil on a clean shutdown (ctx cancelled) or after a one-shot
// subcommand succeeds.
func Run(ctx context.Context, env Env) error {
	if len(env.Args) > 0 {
		switch env.Args[0] {
		case "version":
			fmt.Fprintln(env.Stdout, version.String())
			return nil
		case "healthcheck":
			return healthcheck(ctx, env)
		}
	}

	cfg, err := config.Load(env.Args, env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	return serve(ctx, cfg, env)
}

func serve(ctx context.Context, cfg config.Config, env Env) (err error) {
	log := newLogger(cfg, env.Stdout)

	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer func() {
		// Flushes the on-disk store; report a failed flush if nothing
		// else already went wrong.
		if cerr := st.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing store: %w", cerr)
		}
	}()

	gen := ids.New()
	projectID, err := resolveProjectID(cfg, gen)
	if err != nil {
		return err
	}

	engine := lifecycle.New(lifecycle.Options{Delay: cfg.LifecycleDelay, Logger: log})
	engineCtx, stopEngine := context.WithCancel(context.Background())
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		engine.Run(engineCtx)
	}()
	defer func() {
		stopEngine()
		<-engineDone
	}()

	objectDir, removeObjectDir, err := objectDataDir(cfg)
	if err != nil {
		return err
	}
	defer removeObjectDir()

	services, err := buildServices(ctx, cfg, projectID, objectDir, st, engine, gen, log)
	if err != nil {
		return err
	}

	srv, err := server.New(server.Options{
		Config:    cfg,
		ProjectID: projectID,
		Logger:    log,
		Store:     st,
		Engine:    engine,
		IDs:       gen,
		Services:  services,
	})
	if err != nil {
		return err
	}

	listeners, err := listen(ctx, cfg, log)
	if err != nil {
		return err
	}
	ln := listeners[0]

	httpSrv := &http.Server{
		Handler: srv.Handler(),
		// Guards against slow-header connections. There is deliberately
		// no overall read/write timeout: object uploads and downloads
		// may legitimately take minutes.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	log.Info("weistack started",
		"version", version.Version,
		"address", ln.Addr().String(),
		"ipv6_loopback", len(listeners) > 1,
		"region", cfg.Region,
		"project_id", projectID,
		"persist", cfg.Persist,
		"lifecycle_delay", cfg.LifecycleDelay.String(),
		"services", srv.ServiceNames(),
	)
	if env.OnReady != nil {
		env.OnReady(ln.Addr())
	}

	serveErr := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() { serveErr <- httpSrv.Serve(l) }()
	}

	select {
	case err := <-serveErr:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
	}

	// Graceful shutdown: stop accepting, let in-flight requests finish.
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		_ = httpSrv.Close()
		return fmt.Errorf("shutdown did not finish within %s: %w", cfg.ShutdownTimeout, err)
	}
	log.Info("stopped")
	return nil
}

// buildServices constructs every emulated service. New services are
// added here.
func buildServices(
	ctx context.Context, cfg config.Config, projectID, objectDir string,
	st store.Store, engine *lifecycle.Engine, gen *ids.Generator, log *slog.Logger,
) ([]server.Service, error) {
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log})
	if err != nil {
		return nil, err
	}
	// With persistence on, finish transitions interrupted by the last stop.
	if err := vpcSvc.Resume(ctx); err != nil {
		return nil, err
	}

	imsSvc, err := ims.New(ims.Deps{
		Store: st, Engine: engine, IDs: gen, Logger: log,
		DefaultProjectID: projectID, SeedDir: cfg.SeedDir,
	})
	if err != nil {
		return nil, err
	}
	if err := imsSvc.Resume(ctx); err != nil {
		return nil, err
	}

	ecsSvc, err := ecs.New(ecs.Deps{
		Store: st, Engine: engine, IDs: gen, Logger: log, SeedDir: cfg.SeedDir,
		Network: vpcSvc, Images: imsSvc,
		Quota: ecs.Quota{Servers: cfg.ECSMaxServers, VCPUs: cfg.ECSMaxVCPUs},
	})
	if err != nil {
		return nil, err
	}
	if err := ecsSvc.Resume(ctx); err != nil {
		return nil, err
	}
	// IMS makes images of ECS servers; ECS reads IMS images. The cycle
	// is closed here, after both exist.
	imsSvc.SetServers(ecsSvc)

	obsSvc, err := obs.New(obs.Deps{Store: st, IDs: gen, Logger: log, DataDir: objectDir})
	if err != nil {
		return nil, err
	}
	return []server.Service{vpcSvc, imsSvc, ecsSvc, obsSvc}, nil
}

// objectDataDir returns the directory for OBS object bodies and a
// function to call at exit. With persistence the bodies live beside the
// database; without it they go to a temporary directory that is removed
// when the emulator stops, like the rest of its in-memory state.
func objectDataDir(cfg config.Config) (dir string, cleanup func(), err error) {
	if cfg.Persist {
		return filepath.Join(cfg.DataDir, objectsDir), func() {}, nil
	}
	dir, err = os.MkdirTemp("", "weistack-objects-")
	if err != nil {
		return "", nil, fmt.Errorf("creating a temporary directory for object data: %w", err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// listen opens the server's listeners. The first is always the
// configured address. When that is the default IPv4 loopback, the IPv6
// loopback is opened on the same port as well, because many systems
// resolve "localhost" and "{service}.localhost" to ::1. That second
// listener is best effort: a machine without IPv6 simply does not get it.
func listen(ctx context.Context, cfg config.Config, log *slog.Logger) ([]net.Listener, error) {
	var lc net.ListenConfig
	primary, err := lc.Listen(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("listening: %w", err)
	}
	listeners := []net.Listener{primary}
	if cfg.Host != config.DefaultHost {
		return listeners, nil
	}

	tcp, ok := primary.Addr().(*net.TCPAddr)
	if !ok {
		return listeners, nil
	}
	v6, err := lc.Listen(ctx, "tcp6", net.JoinHostPort("::1", strconv.Itoa(tcp.Port)))
	if err != nil {
		log.Debug("not listening on the IPv6 loopback", "error", err)
		return listeners, nil
	}
	return append(listeners, v6), nil
}

func newLogger(cfg config.Config, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func openStore(cfg config.Config) (store.Store, error) {
	if !cfg.Persist {
		return store.NewMemory(), nil
	}
	return store.OpenBolt(filepath.Join(cfg.DataDir, databaseFile))
}

var projectIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// resolveProjectID returns the configured project ID, or generates one.
// With persistence on, a generated ID is saved so it survives restarts
// and clients configured against it keep working.
func resolveProjectID(cfg config.Config, gen *ids.Generator) (string, error) {
	if cfg.ProjectID != "" {
		return cfg.ProjectID, nil
	}
	if !cfg.Persist {
		return gen.Hex32(), nil
	}

	path := filepath.Join(cfg.DataDir, projectIDFile)
	raw, err := os.ReadFile(path) //nolint:gosec // path is the operator-chosen data directory
	switch {
	case err == nil:
		id := strings.TrimSpace(string(raw))
		if !projectIDRE.MatchString(id) {
			return "", fmt.Errorf("%s does not contain a valid project ID; delete it to generate a new one", path)
		}
		return id, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("reading project ID: %w", err)
	}

	id := gen.Hex32()
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return "", fmt.Errorf("creating data directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("saving project ID: %w", err)
	}
	return id, nil
}

// healthcheck probes a running emulator and fails unless it is healthy.
// It exists because the distroless image has no curl or shell for a
// Docker HEALTHCHECK to use.
func healthcheck(ctx context.Context, env Env) error {
	cfg, err := config.Load(env.Args[1:], env.Getenv, env.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	host := cfg.Host
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1" // a wildcard bind is reached through loopback
	}
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.Port)) + "/_weistack/health"

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s returned %s", url, res.Status)
	}
	fmt.Fprintln(env.Stdout, "ok")
	return nil
}
