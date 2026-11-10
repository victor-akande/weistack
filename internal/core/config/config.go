// Package config loads WeiStack's runtime configuration.
//
// Precedence, highest first: command-line flags, WEISTACK_* environment
// variables, built-in defaults.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix is prepended to every environment variable WeiStack reads.
const EnvPrefix = "WEISTACK_"

// Defaults.
const (
	DefaultHost            = "127.0.0.1"
	DefaultPort            = 8780
	DefaultRegion          = "ap-southeast-1"
	DefaultDataDir         = "/data"
	DefaultLifecycleDelay  = 2 * time.Second
	DefaultLogFormat       = "json"
	DefaultMaxBodyBytes    = 10 << 20 // 10 MiB; services that stream (OBS) opt out per route.
	DefaultShutdownTimeout = 10 * time.Second
	DefaultECSMaxServers   = 20
	DefaultECSMaxVCPUs     = 80
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Host is the address to bind. Loopback by default so a learner's
	// emulator is not exposed to the network; the Docker image sets 0.0.0.0.
	Host string
	// Port is the TCP port of the single shared listener. 0 picks a free port.
	Port int
	// Region is used when a request does not carry one.
	Region string
	// ProjectID is the default project. Empty means "generate at startup".
	ProjectID string
	// Persist enables the on-disk store under DataDir.
	Persist bool
	// DataDir holds persistent state and OBS object bodies.
	DataDir string
	// SeedDir optionally holds YAML files that extend the built-in seed
	// data (for example images.yaml for IMS public images).
	SeedDir string
	// ECSMaxServers and ECSMaxVCPUs are the per-project ECS quotas.
	ECSMaxServers int
	ECSMaxVCPUs   int
	// LifecycleDelay is how long asynchronous transitions take. 0 is instant.
	LifecycleDelay time.Duration
	// LogLevel is the minimum level logged.
	LogLevel slog.Level
	// LogFormat is "json" or "text".
	LogFormat string
	// Services restricts which services are enabled. Empty means all.
	Services []string
	// Metrics enables the Prometheus-format metrics endpoint.
	Metrics bool
	// MaxBodyBytes caps request bodies on JSON APIs.
	MaxBodyBytes int64
	// ShutdownTimeout bounds how long in-flight requests may drain.
	ShutdownTimeout time.Duration
}

var (
	regionRE    = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)
	projectIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	serviceRE   = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
)

// Load resolves the configuration from args (without the program name) and
// the environment exposed by getenv. Usage and flag errors are written to
// stderr. It returns flag.ErrHelp when -h/--help was requested.
func Load(args []string, getenv func(string) string, stderr io.Writer) (Config, error) {
	env := envReader{getenv: getenv}

	var (
		cfg      Config
		logLevel string
		services string
	)

	fs := flag.NewFlagSet("weistack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Host, "host", env.str("HOST", DefaultHost), "address to bind")
	fs.IntVar(&cfg.Port, "port", env.int("PORT", DefaultPort), "port to listen on (0 picks a free port)")
	fs.StringVar(&cfg.Region, "region", env.str("REGION", DefaultRegion), "default region")
	fs.StringVar(&cfg.ProjectID, "project-id", env.str("PROJECT_ID", ""), "default project ID, 32 hex characters (generated when empty)")
	fs.BoolVar(&cfg.Persist, "persist", env.bool("PERSIST", false), "persist state under the data directory")
	fs.StringVar(&cfg.DataDir, "data-dir", env.str("DATA_DIR", DefaultDataDir), "directory for persistent state and object bodies")
	fs.StringVar(&cfg.SeedDir, "seed-dir", env.str("SEED_DIR", ""), "directory of YAML files that extend the built-in seed data")
	fs.IntVar(&cfg.ECSMaxServers, "ecs-max-servers", env.int("ECS_MAX_SERVERS", DefaultECSMaxServers), "per-project quota of ECS servers")
	fs.IntVar(&cfg.ECSMaxVCPUs, "ecs-max-vcpus", env.int("ECS_MAX_VCPUS", DefaultECSMaxVCPUs), "per-project quota of ECS vCPUs")
	fs.DurationVar(&cfg.LifecycleDelay, "lifecycle-delay", env.duration("LIFECYCLE_DELAY", DefaultLifecycleDelay), "duration of asynchronous state transitions (0 is instant)")
	fs.StringVar(&logLevel, "log-level", env.str("LOG_LEVEL", "info"), "log level: debug, info, warn or error")
	fs.StringVar(&cfg.LogFormat, "log-format", env.str("LOG_FORMAT", DefaultLogFormat), "log format: json or text")
	fs.StringVar(&services, "services", env.str("SERVICES", ""), "comma-separated services to enable (default all)")
	fs.BoolVar(&cfg.Metrics, "metrics", env.bool("METRICS", false), "serve Prometheus metrics at /_weistack/metrics")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", env.int64("MAX_BODY_BYTES", DefaultMaxBodyBytes), "maximum request body size for JSON APIs")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", env.duration("SHUTDOWN_TIMEOUT", DefaultShutdownTimeout), "time allowed for in-flight requests to finish on shutdown")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if env.err != nil {
		return Config{}, env.err
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return Config{}, fmt.Errorf("invalid log level %q: want debug, info, warn or error", logLevel)
	}
	cfg.LogFormat = strings.ToLower(cfg.LogFormat)
	cfg.Services = splitList(services)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports every problem with the configuration at once.
func (c Config) Validate() error {
	var errs []error
	if c.Port < 0 || c.Port > 65535 {
		errs = append(errs, fmt.Errorf("port %d is out of range 0-65535", c.Port))
	}
	if !regionRE.MatchString(c.Region) {
		errs = append(errs, fmt.Errorf("region %q is not a valid region name (for example %s)", c.Region, DefaultRegion))
	}
	if c.ProjectID != "" && !projectIDRE.MatchString(c.ProjectID) {
		errs = append(errs, fmt.Errorf("project ID %q must be 32 lowercase hex characters", c.ProjectID))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data directory must not be empty"))
	}
	if c.ECSMaxServers < 1 || c.ECSMaxVCPUs < 1 {
		errs = append(errs, fmt.Errorf("ECS quotas must be positive (servers %d, vCPUs %d)", c.ECSMaxServers, c.ECSMaxVCPUs))
	}
	if c.LifecycleDelay < 0 {
		errs = append(errs, fmt.Errorf("lifecycle delay %s must not be negative", c.LifecycleDelay))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, fmt.Errorf("log format %q must be json or text", c.LogFormat))
	}
	for _, s := range c.Services {
		if !serviceRE.MatchString(s) {
			errs = append(errs, fmt.Errorf("service name %q is not valid", s))
		}
	}
	if c.MaxBodyBytes <= 0 {
		errs = append(errs, fmt.Errorf("max body bytes %d must be positive", c.MaxBodyBytes))
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, fmt.Errorf("shutdown timeout %s must be positive", c.ShutdownTimeout))
	}
	return errors.Join(errs...)
}

// ServiceEnabled reports whether the named service should be started.
func (c Config) ServiceEnabled(name string) bool {
	if len(c.Services) == 0 {
		return true
	}
	for _, s := range c.Services {
		if s == name {
			return true
		}
	}
	return false
}

// splitList parses a comma-separated list, trimming blanks, lower-casing
// and dropping duplicates while keeping first-seen order.
func splitList(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
}

// envReader reads typed environment variables, remembering the first error
// so flag defaults can be declared inline.
type envReader struct {
	getenv func(string) string
	err    error
}

func (e *envReader) lookup(key string) (string, bool) {
	v := strings.TrimSpace(e.getenv(EnvPrefix + key))
	return v, v != ""
}

func (e *envReader) fail(key, value, want string) {
	if e.err == nil {
		e.err = fmt.Errorf("invalid %s%s=%q: want %s", EnvPrefix, key, value, want)
	}
}

func (e *envReader) str(key, def string) string {
	if v, ok := e.lookup(key); ok {
		return v
	}
	return def
}

func (e *envReader) int(key string, def int) int {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.fail(key, v, "an integer")
		return def
	}
	return n
}

func (e *envReader) int64(key string, def int64) int64 {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		e.fail(key, v, "an integer")
		return def
	}
	return n
}

func (e *envReader) bool(key string, def bool) bool {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.fail(key, v, "a boolean (1, 0, true, false)")
		return def
	}
	return b
}

// duration accepts Go durations ("2s", "500ms") and bare numbers, which
// are read as seconds so WEISTACK_LIFECYCLE_DELAY=0 works.
func (e *envReader) duration(key string, def time.Duration) time.Duration {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	if secs, err := strconv.ParseFloat(v, 64); err == nil {
		return time.Duration(secs * float64(time.Second))
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.fail(key, v, `a duration such as "2s" or a number of seconds`)
		return def
	}
	return d
}
