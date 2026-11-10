// Package version exposes build metadata injected at link time.
package version

import "fmt"

// These variables are overridden with -ldflags "-X" by the Makefile, the
// Dockerfile and the release tooling.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line, human-readable build description.
func String() string {
	return fmt.Sprintf("weistack %s (commit %s, built %s)", Version, Commit, Date)
}
