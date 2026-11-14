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
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/hostpattern"
	"github.com/victor-akande/weistack/internal/core/identity"
)

// EnvPrefix is prepended to every environment variable WeiStack reads.
const EnvPrefix = "WEISTACK_"

// Defaults.
const (
	DefaultHost           = "127.0.0.1"
	DefaultPort           = 8780
	DefaultRegion         = "ap-southeast-1"
	DefaultLifecycleDelay = 2 * time.Second
	// DefaultLogFormat picks text at a terminal and JSON otherwise.
	DefaultLogFormat       = "auto"
	DefaultMaxBodyBytes    = 10 << 20 // 10 MiB; services that stream (OBS) opt out per route.
	DefaultShutdownTimeout = 10 * time.Second
	DefaultECSMaxServers   = 20
	DefaultECSMaxVCPUs     = 80
	DefaultRDSMaxInstances = 20
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
	// RDSMaxInstances is the per-project RDS instance quota.
	RDSMaxInstances int
	// LifecycleDelay is how long asynchronous transitions take. 0 is instant.
	LifecycleDelay time.Duration
	// LogLevel is the minimum level logged.
	LogLevel slog.Level
	// LogFormat is "json", "text" or "auto" (text at a terminal).
	LogFormat string
	// Services restricts which services are enabled. Empty means all.
	Services []string
	// ProxyDomains are the domains WeiStack answers for when clients use
	// it as an HTTP(S) proxy.
	ProxyDomains []string
	// ProxyBypass are host patterns inside ProxyDomains that WeiStack
	// does not answer for: tooling downloads such as KooCLI's catalogue.
	// They are treated like any other host outside the domains.
	ProxyBypass []string
	// ProxyPassthrough says who may tunnel through WeiStack to other
	// hosts: loopback (clients on this machine), all, or none.
	ProxyPassthrough string
	// TLSDir holds the local CA, and the bootstrap administrator's
	// credentials beside it. Empty means the default location.
	TLSDir string
	// AdminAccessKey and AdminSecretKey fix the bootstrap administrator's
	// keys instead of the generated ones, for example in CI. Both or
	// neither.
	AdminAccessKey string
	AdminSecretKey string
	// IAM is how credentials are treated: IAMAccept takes any, as v0.1
	// did; IAMEnforce requires a valid signature or token on every
	// request to an emulated service.
	IAM string
	// ServicePorts gives services a listener of their own, on which every
	// request goes to that service: for clients that cannot address a
	// service by host name or path prefix. Keyed by service name.
	ServicePorts map[string]int
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
	domainRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// Load resolves the configuration from args (without the program name) and
// the environment exposed by getenv. Usage and flag errors are written to
// stderr. It returns flag.ErrHelp when -h/--help was requested.
func Load(args []string, getenv func(string) string, stderr io.Writer) (Config, error) {
	env := envReader{getenv: getenv}

	var (
		cfg          Config
		logLevel     string
		services     string
		servicePorts string
		proxyDomains string
		proxyBypass  string
	)

	fs := flag.NewFlagSet("weistack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Host, "host", env.str("HOST", DefaultHost), "address to bind")
	fs.IntVar(&cfg.Port, "port", env.int("PORT", DefaultPort), "port to listen on (0 picks a free port)")
	fs.StringVar(&cfg.Region, "region", env.str("REGION", DefaultRegion), "default region")
	fs.StringVar(&cfg.ProjectID, "project-id", env.str("PROJECT_ID", ""), "default project ID, 32 hex characters (generated when empty)")
	fs.BoolVar(&cfg.Persist, "persist", env.bool("PERSIST", false), "persist state under the data directory")
	fs.StringVar(&cfg.DataDir, "data-dir", env.str("DATA_DIR", DefaultDataDir(getenv)), "directory for persistent state and object bodies, with -persist")
	fs.StringVar(&cfg.SeedDir, "seed-dir", env.str("SEED_DIR", ""), "directory of YAML files that extend the built-in seed data")
	fs.IntVar(&cfg.ECSMaxServers, "ecs-max-servers", env.int("ECS_MAX_SERVERS", DefaultECSMaxServers), "per-project quota of ECS servers")
	fs.IntVar(&cfg.ECSMaxVCPUs, "ecs-max-vcpus", env.int("ECS_MAX_VCPUS", DefaultECSMaxVCPUs), "per-project quota of ECS vCPUs")
	fs.IntVar(&cfg.RDSMaxInstances, "rds-max-instances", env.int("RDS_MAX_INSTANCES", DefaultRDSMaxInstances), "per-project quota of RDS instances")
	fs.DurationVar(&cfg.LifecycleDelay, "lifecycle-delay", env.duration("LIFECYCLE_DELAY", DefaultLifecycleDelay), "duration of asynchronous state transitions (0 is instant)")
	fs.StringVar(&logLevel, "log-level", env.str("LOG_LEVEL", "info"), "log level: debug, info, warn or error")
	fs.StringVar(&cfg.LogFormat, "log-format", env.str("LOG_FORMAT", DefaultLogFormat), "log format: json, text, or auto for text at a terminal")
	fs.StringVar(&proxyDomains, "proxy-domains", env.str("PROXY_DOMAINS", "myhuaweicloud.com"), "domains answered when WeiStack is used as an HTTPS proxy")
	fs.StringVar(&proxyBypass, "proxy-bypass", env.str("PROXY_BYPASS", strings.Join(DefaultProxyBypass, ",")),
		"hosts inside the proxy domains that are passed on, not answered: * is one label, {region} the same label everywhere")
	fs.StringVar(&cfg.ProxyPassthrough, "proxy-passthrough", env.str("PROXY_PASSTHROUGH", "loopback"), "who may tunnel to other hosts through the proxy: loopback, all or none")
	fs.StringVar(&cfg.AdminAccessKey, "admin-access-key", env.str("ADMIN_ACCESS_KEY", ""), "the administrator's access key, instead of the generated one")
	fs.StringVar(&cfg.AdminSecretKey, "admin-secret-key", env.str("ADMIN_SECRET_KEY", ""), "the administrator's secret key (prefer WEISTACK_ADMIN_SECRET_KEY: flags show in process lists)")
	fs.StringVar(&cfg.IAM, "iam", env.str("IAM", IAMAccept), "credentials: accept (any, as before) or enforce (a valid signature or IAM token on every request)")
	fs.StringVar(&cfg.TLSDir, "tls-dir", env.str("TLS_DIR", ""), "directory of the local CA (default: weistack/tls in the user config directory)")
	fs.StringVar(&servicePorts, "service-ports", env.str("SERVICE_PORTS", ""), "extra per-service listeners, for example obs=9000,ecs=9001")
	fs.StringVar(&services, "services", env.str("SERVICES", ""), "comma-separated services to enable (default all)")
	fs.BoolVar(&cfg.Metrics, "metrics", env.bool("METRICS", false), "serve Prometheus metrics at /_weistack/metrics")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", env.int64("MAX_BODY_BYTES", DefaultMaxBodyBytes), "maximum request body size for JSON APIs")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", env.duration("SHUTDOWN_TIMEOUT", DefaultShutdownTimeout), "time allowed for in-flight requests to finish on shutdown")

	err := fs.Parse(args)
	if err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if env.err != nil {
		return Config{}, env.err
	}

	if err = cfg.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return Config{}, fmt.Errorf("invalid log level %q: want debug, info, warn or error", logLevel)
	}
	cfg.LogFormat = strings.ToLower(cfg.LogFormat)
	cfg.Services = splitList(services)
	cfg.ProxyDomains = splitList(proxyDomains)
	cfg.ProxyBypass = splitList(proxyBypass)
	if cfg.ServicePorts, err = parseServicePorts(servicePorts); err != nil {
		return Config{}, err
	}

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
	if c.Persist && c.DataDir == "" {
		errs = append(errs, errors.New("no data directory for -persist: set -data-dir"))
	}
	switch c.IAM {
	case IAMAccept, IAMEnforce:
	default:
		errs = append(errs, fmt.Errorf("iam mode %q must be accept or enforce", c.IAM))
	}
	switch c.ProxyPassthrough {
	case "loopback", "all", "none":
	default:
		errs = append(errs, fmt.Errorf("proxy passthrough %q must be loopback, all or none", c.ProxyPassthrough))
	}
	for _, d := range c.ProxyDomains {
		if !domainRE.MatchString(d) {
			errs = append(errs, fmt.Errorf("proxy domain %q is not a domain name", d))
		}
	}
	for _, p := range c.ProxyBypass {
		if _, err := hostpattern.Compile(p); err != nil {
			errs = append(errs, fmt.Errorf("proxy bypass: %w", err))
		}
	}
	if c.RDSMaxInstances < 1 {
		errs = append(errs, fmt.Errorf("RDS instance quota %d must be positive", c.RDSMaxInstances))
	}
	if c.ECSMaxServers < 1 || c.ECSMaxVCPUs < 1 {
		errs = append(errs, fmt.Errorf("ECS quotas must be positive (servers %d, vCPUs %d)", c.ECSMaxServers, c.ECSMaxVCPUs))
	}
	if c.LifecycleDelay < 0 {
		errs = append(errs, fmt.Errorf("lifecycle delay %s must not be negative", c.LifecycleDelay))
	}
	switch {
	case (c.AdminAccessKey == "") != (c.AdminSecretKey == ""):
		errs = append(errs, errors.New("set both the administrator's access key and secret key, or neither"))
	case c.AdminAccessKey != "" && (!identity.ValidKey(c.AdminAccessKey) || !identity.ValidKey(c.AdminSecretKey)):
		errs = append(errs, errors.New("the administrator's keys must be 8 to 128 letters and digits"))
	}
	switch c.LogFormat {
	case "json", "text", "auto":
	default:
		errs = append(errs, fmt.Errorf("log format %q must be json, text or auto", c.LogFormat))
	}
	used := map[int]string{c.Port: "the main listener"}
	for name, port := range c.ServicePorts {
		switch {
		case !serviceRE.MatchString(name):
			errs = append(errs, fmt.Errorf("service name %q in the service ports is not valid", name))
		case port < 1 || port > 65535:
			errs = append(errs, fmt.Errorf("port %d for %s is out of range 1-65535", port, name))
		case used[port] != "" && port != 0:
			errs = append(errs, fmt.Errorf("port %d for %s is already used by %s", port, name, used[port]))
		}
		used[port] = name
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

// parseServicePorts reads "obs=9000,ecs=9001".
func parseServicePorts(raw string) (map[string]int, error) {
	out := map[string]int{}
	for _, part := range splitList(raw) {
		name, port, ok := strings.Cut(part, "=")
		n, err := strconv.Atoi(strings.TrimSpace(port))
		if !ok || err != nil {
			return nil, fmt.Errorf("invalid service port %q: want service=port, for example obs=9000", part)
		}
		if _, dup := out[strings.TrimSpace(name)]; dup {
			return nil, fmt.Errorf("service %q is given more than one port", name)
		}
		out[strings.TrimSpace(name)] = n
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

// IAM modes.
const (
	IAMAccept  = "accept"
	IAMEnforce = "enforce"
)

// DefaultProxyBypass are the hosts under myhuaweicloud.com that Huawei's
// tools download from before they call any API: KooCLI's version file and
// API metadata (an OBS bucket per region) and API Explorer's catalogue.
// They carry no API traffic, so passing them through lets the tools start
// without letting a request for an unemulated service escape.
var DefaultProxyBypass = []string{
	"{region}-hwcloudcli.obs.{region}.myhuaweicloud.com",
	"apiexplorer.*.myhuaweicloud.com",
}

// DefaultDataDir is where -persist keeps state when -data-dir is not
// given: the per-user data directory of the platform, for example
// ~/.local/share/weistack on Linux. It is empty when the home directory
// is unknown. The container image sets /data instead.
func DefaultDataDir(getenv func(string) string) string {
	if dir := getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "weistack")
	}
	switch runtime.GOOS {
	case "windows":
		if dir := getenv("LocalAppData"); dir != "" {
			return filepath.Join(dir, "weistack")
		}
		return ""
	case "darwin":
		if home := getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "weistack")
		}
		return ""
	}
	if home := getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "share", "weistack")
	}
	return ""
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
