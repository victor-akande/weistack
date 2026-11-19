// Package faults holds the failures a user asks WeiStack to inject,
// through the admin API (/_weistack/faults), to see how a client copes:
//
//   - lifecycle faults make the next transitions of a kind (a server's
//     build, an RDS instance's creation...) fail, so the resource ends in
//     its error state, as the lifecycle engine's FaultInjector;
//   - request faults answer the next requests matching a service, method
//     and path with an error, such as API Gateway's throttling, after an
//     optional delay, or only delay them.
//
// A rule applies a number of times (once by default) or until removed.
package faults

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule types.
const (
	TypeLifecycle = "lifecycle"
	TypeRequest   = "request"
)

// Rule is one fault to inject.
type Rule struct {
	ID   string `json:"id"`
	Type string `json:"type"`

	// Transition is a lifecycle kind, or a pattern of them
	// (ecs.server.*); Resource, if set, limits it to one resource ID.
	Transition string `json:"transition,omitempty"`
	Resource   string `json:"resource,omitempty"`

	// Service, Method and Path select requests: a service's name, an
	// HTTP method (any if empty) and a path pattern (any if empty), where
	// * matches one path segment, as in /v1/*/vpcs.
	Service string `json:"service,omitempty"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	// Status, Code and Message are the error to answer with; Status 0
	// with a delay only delays the request.
	Status  int    `json:"status,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	// DelayMS delays the request, or the error, by this many
	// milliseconds.
	DelayMS int `json:"delay_ms,omitempty"`

	// Times is how many times the rule applies; 0 means until removed.
	// Remaining counts down.
	Times     int `json:"times"`
	Remaining int `json:"remaining"`
	// Hits counts how many times the rule has applied.
	Hits int `json:"hits"`

	Created time.Time `json:"created"`
}

// Delay is the rule's delay.
func (r Rule) Delay() time.Duration { return time.Duration(r.DelayMS) * time.Millisecond }

// Limits.
const (
	MaxDelayMS = 60_000
	MaxRules   = 100
)

var transitionRE = regexp.MustCompile(`^[a-z0-9*]+(\.[a-z0-9*]+)*$`)

// ErrInvalid wraps the reason a rule is refused.
var ErrInvalid = errors.New("faults: invalid rule")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Check validates a rule as given, before Add fills it in.
func Check(r Rule) error {
	if r.Times < 0 {
		return invalid("times must be 0 (until removed) or more")
	}
	if r.DelayMS < 0 || r.DelayMS > MaxDelayMS {
		return invalid("delay_ms must be between 0 and %d", MaxDelayMS)
	}
	switch r.Type {
	case TypeLifecycle:
		if !transitionRE.MatchString(r.Transition) {
			return invalid("transition must be a lifecycle kind such as ecs.server.build, or a pattern such as ecs.server.*")
		}
		if r.Service != "" || r.Method != "" || r.Path != "" || r.Status != 0 || r.Code != "" || r.DelayMS != 0 {
			return invalid("a lifecycle fault takes transition, resource and times only")
		}
	case TypeRequest:
		if r.Service == "" {
			return invalid("a request fault needs a service")
		}
		if r.Transition != "" || r.Resource != "" {
			return invalid("a request fault takes no transition or resource")
		}
		if r.Path != "" {
			if _, err := path.Match(r.Path, "/"); err != nil || r.Path[0] != '/' {
				return invalid("path must be a pattern starting with /")
			}
		}
		if r.Status == 0 && r.DelayMS == 0 {
			return invalid("a request fault needs a status, a delay or both")
		}
		if r.Status != 0 && (r.Status < 400 || r.Status > 599) {
			return invalid("status must be an HTTP error status, 400 to 599")
		}
		if r.Status == 0 && (r.Code != "" || r.Message != "") {
			return invalid("code and message need a status")
		}
	default:
		return invalid("type must be lifecycle or request")
	}
	return nil
}

// Registry holds the rules. It is safe for concurrent use.
type Registry struct {
	now func() time.Time

	mu    sync.Mutex
	seq   int
	rules []Rule
}

// New returns an empty registry. now defaults to time.Now.
func New(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{now: now}
}

// Add validates a rule and adds it, returning it as stored.
func (g *Registry) Add(r Rule) (Rule, error) {
	if err := Check(r); err != nil {
		return Rule{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.rules) >= MaxRules {
		return Rule{}, invalid("at most %d rules", MaxRules)
	}
	g.seq++
	r.Method = strings.ToUpper(r.Method)
	r.ID, r.Remaining, r.Hits, r.Created = strconv.Itoa(g.seq), r.Times, 0, g.now().UTC()
	if r.Times == 0 {
		r.Remaining = -1
	}
	g.rules = append(g.rules, r)
	return r, nil
}

// List returns the rules in the order they were added.
func (g *Registry) List() []Rule {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Rule{}, g.rules...)
}

// Remove deletes a rule; it reports whether there was one.
func (g *Registry) Remove(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, r := range g.rules {
		if r.ID == id {
			g.rules = append(g.rules[:i], g.rules[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes every rule.
func (g *Registry) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rules = nil
}

// take applies the first rule match accepts, counting it down and
// dropping it once spent.
func (g *Registry) take(match func(Rule) bool) (Rule, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.rules {
		r := &g.rules[i]
		if !match(*r) {
			continue
		}
		r.Hits++
		applied := *r
		if r.Remaining > 0 {
			r.Remaining--
			applied.Remaining = r.Remaining
			if r.Remaining == 0 {
				g.rules = append(g.rules[:i], g.rules[i+1:]...)
			}
		}
		return applied, true
	}
	return Rule{}, false
}

// Fault implements lifecycle.FaultInjector.
func (g *Registry) Fault(kind, key string) error {
	r, ok := g.take(func(r Rule) bool {
		if r.Type != TypeLifecycle || r.Resource != "" && r.Resource != key {
			return false
		}
		m, _ := path.Match(r.Transition, kind)
		return m
	})
	if !ok {
		return nil
	}
	return fmt.Errorf("injected fault %s on %s", r.ID, kind)
}

// Request returns the request fault to apply to a request of service,
// with method and service-relative path, if any.
func (g *Registry) Request(service, method, p string) (Rule, bool) {
	return g.take(func(r Rule) bool {
		if r.Type != TypeRequest || r.Service != service || r.Method != "" && r.Method != method {
			return false
		}
		if r.Path == "" {
			return true
		}
		m, _ := path.Match(r.Path, p)
		return m
	})
}
