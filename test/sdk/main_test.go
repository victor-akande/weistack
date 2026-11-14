// Package sdk drives a running WeiStack with Huawei Cloud's official Go
// SDK. It is the proof of wire compatibility: the SDK signs requests,
// builds URLs and decodes responses exactly as it would against the
// real cloud.
//
// The suite lives in its own Go module so the SDK, which is very large,
// never becomes a dependency of the emulator itself.
//
// By default TestMain builds the emulator from this repository and
// starts it on a free port. Set WEISTACK_ADDR=host:port to test an
// emulator that is already running (for example the Docker image); it
// must use the project ID in WEISTACK_PROJECT_ID.
package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	region           = "ap-southeast-1"
	defaultProjectID = "0123456789abcdef0123456789abcdef"
	// lifecycleDelay is long enough that tests really observe the
	// transient states and short enough to keep the suite quick.
	lifecycleDelay = 150 * time.Millisecond
)

var (
	// emulatorAddr is the host:port every SDK connection is dialled to.
	emulatorAddr string
	// emulatorBin is the binary the suite built, empty when it tests an
	// emulator that was already running (WEISTACK_ADDR).
	emulatorBin string
	projectID   = defaultProjectID
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if addr := os.Getenv("WEISTACK_ADDR"); addr != "" {
		emulatorAddr = addr
		if id := os.Getenv("WEISTACK_PROJECT_ID"); id != "" {
			projectID = id
		}
		if err := waitHealthy(emulatorAddr, 10*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "sdk tests:", err)
			return 1
		}
		return m.Run()
	}

	stop, err := startEmulator()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sdk tests:", err)
		return 1
	}
	defer stop()
	return m.Run()
}

// startEmulator builds the emulator from the repository root and runs it
// on a free loopback port as the suite's shared instance.
func startEmulator() (stop func(), err error) {
	dir, err := os.MkdirTemp("", "weistack-sdk-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	emulatorBin, err = buildEmulator(dir)
	if err != nil {
		cleanup()
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		cleanup()
		return nil, err
	}
	e, err := launch(emulatorBin, port, append([]string{
		"WEISTACK_TLS_DIR=" + filepath.Join(dir, "tls"),
		"WEISTACK_LIFECYCLE_DELAY=" + lifecycleDelay.String(),
	}, emulatorIAMEnv()...)...)
	if err != nil {
		cleanup()
		return nil, err
	}
	emulatorAddr = e.addr
	return func() { _ = e.stop(); cleanup() }, nil
}

// buildEmulator builds the emulator from the repository root into dir.
func buildEmulator(dir string) (string, error) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "weistack")
	build := exec.Command("go", "build", "-o", bin, "./cmd/weistack")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building the emulator: %w\n%s", err, out)
	}
	return bin, nil
}

// emulator is a running emulator process.
type emulator struct {
	cmd  *exec.Cmd
	addr string
	done chan struct{}
}

// launch runs bin on a loopback port with the suite's project and
// region, plus env, and waits until it is healthy.
func launch(bin, port string, env ...string) (*emulator, error) {
	cmd := exec.Command(bin)
	cmd.Env = append(append(os.Environ(),
		"WEISTACK_PORT="+port,
		"WEISTACK_PROJECT_ID="+projectID,
		"WEISTACK_REGION="+region,
		"WEISTACK_LOG_LEVEL=warn",
	), env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the emulator: %w", err)
	}
	e := &emulator{cmd: cmd, addr: net.JoinHostPort("127.0.0.1", port), done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(e.done) }()
	if err := waitHealthy(e.addr, 15*time.Second); err != nil {
		e.kill()
		return nil, err
	}
	return e, nil
}

// stop shuts the emulator down gracefully, as SIGINT or SIGTERM does,
// and reports whether it exited in time.
func (e *emulator) stop() error {
	_ = e.cmd.Process.Signal(os.Interrupt)
	select {
	case <-e.done:
		if code := e.cmd.ProcessState.ExitCode(); code != 0 {
			return fmt.Errorf("emulator exited %d", code)
		}
		return nil
	case <-time.After(15 * time.Second):
		e.kill()
		return errors.New("emulator did not stop within 15s")
	}
}

// kill ends the emulator at once, as a crash or an OOM kill would.
func (e *emulator) kill() {
	_ = e.cmd.Process.Kill()
	<-e.done
}

func freePort() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	return port, err
}

func waitHealthy(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := "http://" + addr + "/_weistack/health"
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		res, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("emulator at %s did not become healthy: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
