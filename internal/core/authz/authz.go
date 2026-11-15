// Package authz authorizes requests under -iam=enforce: it decides, with
// the policies IAM says a principal holds, whether the principal may
// perform an operation, and renders a denial in the service's own error
// envelope.
//
// Three pieces meet in a request's context:
//
//   - The server attaches a [Gate] after authenticating the caller. Without
//     one (the default -iam=accept mode) every check passes at no cost.
//   - Each service declares, with [Service], how its denials look.
//   - Each route declares its action with [Action] (or [Public] for the
//     documented operations that need no permission), and handlers that
//     learn their action from the body call [Check].
package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/actions"
	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/policy"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

// Scope is where a request acts: its service, region and, for services
// whose resources live in projects, the project in its path (empty when
// the path has none, as for IMS: IAM then uses the region's project).
type Scope struct {
	Service   string
	Region    string
	ProjectID string
	// Global marks a global service (OBS, IAM, EPS, STS), which classic
	// grants for global services cover.
	Global bool
}

// Grants are the permissions a principal holds in a scope.
type Grants struct {
	// All marks a principal that holds every permission: the account's
	// root user and the members of the admin group.
	All bool
	// Sources are the policies and roles that apply in the scope.
	Sources []policy.Source
	// Keys are the principal's condition keys (g:UserId, g:UserName,
	// g:DomainId, g:DomainName, g:ProjectId, g:ProjectName), lower case.
	Keys map[string][]string
}

// Provider answers what a principal holds. IAM implements it.
type Provider interface {
	Grants(ctx context.Context, p identity.Principal, s Scope) (Grants, error)
}

// Sealer encrypts denial explanations. The vault implements it.
type Sealer interface {
	Seal(secret, label string) ([]byte, error)
	Open(sealed []byte, label string) (string, error)
}

// sealLabel binds sealed explanations to their purpose.
const sealLabel = "weistack:authorization-message"

// Gate authorizes one request's caller. The server makes one per
// request in enforce mode.
type Gate struct {
	principal identity.Principal
	account   string
	provider  Provider
	sealer    Sealer
	log       *slog.Logger
	now       time.Time
	sourceIP  string

	mu        sync.Mutex
	grants    map[Scope]Grants
	consulted bool
}

// GateOptions configure a Gate.
type GateOptions struct {
	Principal identity.Principal
	// Account is the account (domain) ID, for resource URNs.
	Account  string
	Provider Provider
	Sealer   Sealer
	Log      *slog.Logger
	Now      time.Time
	// SourceIP is the caller's address, for g:SourceIp.
	SourceIP string
}

// NewGate returns a gate for one request.
func NewGate(o GateOptions) *Gate {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Gate{
		principal: o.Principal, account: o.Account, provider: o.Provider, sealer: o.Sealer,
		log: o.Log, now: o.Now, sourceIP: o.SourceIP,
	}
}

// Consulted reports whether a route checked the request or declared it
// public. A request that reaches a handler unconsulted is a route
// without a declared action, which tests forbid.
func (g *Gate) Consulted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.consulted
}

func (g *Gate) markConsulted() {
	g.mu.Lock()
	g.consulted = true
	g.mu.Unlock()
}

type gateKey struct{}

// WithGate returns a copy of ctx carrying g.
func WithGate(ctx context.Context, g *Gate) context.Context {
	return context.WithValue(ctx, gateKey{}, g)
}

// GateFrom returns the gate in ctx, or nil when nothing is enforced.
func GateFrom(ctx context.Context) *Gate {
	g, _ := ctx.Value(gateKey{}).(*Gate)
	return g
}

// Denial explains a refused operation.
type Denial struct {
	Action    string
	Resources []string
	Decision  policy.Decision
	// Encoded is the sealed explanation, for the response's
	// encoded_authorization_message.
	Encoded string
}

// Message is the explanation classic IAM documents for a denial
// (IAM.0003): "Policy doesn't allow <action> to be performed."
func (d *Denial) Message() string {
	return fmt.Sprintf("Policy doesn't allow %s to be performed.", d.Action)
}

// Denier renders a denial as the service's error.
type Denier func(*Denial) *apierr.Error

// Forbidden is the denial of services that document no permission
// error: WeiStack.0403, WeiStack's own code (as WeiStack.0501 is), with
// classic IAM's documented message and the encoded explanation.
func Forbidden(d *Denial) *apierr.Error {
	return apierr.New(http.StatusForbidden, "WeiStack.0403", "%s", d.Message()).WithAuthorizationMessage(d.Encoded)
}

// ServiceOptions describe a service's resources and denials.
type ServiceOptions struct {
	// Name is the service's name in actions and resource URNs.
	Name string
	// Global marks a global service: its URNs have no region, and
	// classic grants for global services apply to it.
	Global bool
	// NoAccount leaves the account out of URNs, as OBS's documented
	// URNs (obs:::bucket:<name>) do.
	NoAccount bool
	// Style is the service's error envelope.
	Style apierr.Style
	// Deny renders its denials; nil means Forbidden.
	Deny Denier
}

type serviceKey struct{}

// Service returns middleware declaring the service of the routes under
// it. Routes of a service with several error envelopes (VPC's v1 and
// v3) declare each in their own group.
func Service(o ServiceOptions) func(http.Handler) http.Handler {
	if o.Deny == nil {
		o.Deny = Forbidden
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), serviceKey{}, &o)))
		})
	}
}

func serviceFrom(ctx context.Context) *ServiceOptions {
	o, _ := ctx.Value(serviceKey{}).(*ServiceOptions)
	return o
}

// Resource names a resource an operation acts on.
type Resource struct {
	// Type is the resource type in the action table, such as "vpc".
	Type string
	// Path is the resource's name in its URN: usually its ID; for OBS
	// objects, bucket/key.
	Path string
}

// ResourceFunc finds a resource of a request.
type ResourceFunc func(*http.Request) (Resource, bool)

// Param is the resource of the given type whose ID is the route's URL
// parameter.
func Param(typ, param string) ResourceFunc {
	return func(r *http.Request) (Resource, bool) {
		id := chi.URLParam(r, param)
		return Resource{Type: typ, Path: id}, id != ""
	}
}

// Action returns middleware that lets a request through only if the
// caller may perform the named action on the resources found. The name
// must be in the action catalogue: a typo panics when routes are built.
func Action(name string, resources ...ResourceFunc) func(http.Handler) http.Handler {
	a := actions.MustLookup(name)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if GateFrom(r.Context()) != nil {
				var res []Resource
				for _, f := range resources {
					if x, ok := f(r); ok {
						res = append(res, x)
					}
				}
				if err := check(r, a, res); err != nil {
					write(w, r, err)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Public returns middleware for routes that need no permission, as
// Huawei documents for signing in or changing one's own password.
func Public() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if g := GateFrom(r.Context()); g != nil {
				g.markConsulted()
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Check reports whether the caller may perform the named action on the
// resources, for handlers that learn their action from the request
// body. It returns nil when allowed or nothing is enforced, and
// otherwise the service's denial, for the handler to return.
func Check(r *http.Request, name string, resources ...Resource) error {
	if GateFrom(r.Context()) == nil {
		return nil
	}
	return check(r, actions.MustLookup(name), resources)
}

// Defer marks a request whose route leaves the check to its handler
// (with Check), once the body says which action it is.
func Defer() func(http.Handler) http.Handler { return Public() }

func write(w http.ResponseWriter, r *http.Request, err error) {
	style := apierr.StyleFlat
	if o := serviceFrom(r.Context()); o != nil {
		style = o.Style
	}
	apierr.Write(w, r, style, err)
}

// check authorizes a against the gate in r's context.
func check(r *http.Request, a actions.Action, res []Resource) error {
	ctx := r.Context()
	g := GateFrom(ctx)
	g.markConsulted()
	if g.principal.Admin {
		return nil
	}
	o := serviceFrom(ctx)
	if o == nil {
		// A route outside any declared service: refuse rather than guess.
		return apierr.Internal(fmt.Errorf("authz: action %s checked outside a service", a.Name))
	}
	scope := Scope{Service: o.Name, Region: reqctx.From(ctx).Region, Global: o.Global}
	if !o.Global {
		scope.ProjectID = chi.URLParam(r, "project_id")
	}
	grants, err := g.grantsFor(ctx, scope)
	if err != nil {
		return err
	}
	if grants.All {
		return nil
	}

	urns := make([]string, 0, len(res))
	for _, x := range res {
		urns = append(urns, g.urn(o, scope, x))
	}
	req := policy.Request{Action: a.Name, Aliases: a.Aliases, Resources: urns, Keys: g.keys(grants.Keys)}
	d := policy.Evaluate(req, grants.Sources)
	if d.Allowed {
		return nil
	}
	denial := &Denial{Action: a.Name, Resources: urns, Decision: d}
	denial.Encoded = g.encode(denial)
	g.log.InfoContext(ctx, "permission denied",
		"action", a.Name, "resources", urns, "user", g.principal.UserName, "reason", d.Failure(),
		"policy", d.Policy)
	return o.Deny(denial)
}

func (g *Gate) grantsFor(ctx context.Context, s Scope) (Grants, error) {
	g.mu.Lock()
	gr, ok := g.grants[s]
	g.mu.Unlock()
	if ok {
		return gr, nil
	}
	if g.provider == nil {
		return Grants{}, nil
	}
	gr, err := g.provider.Grants(ctx, g.principal, s)
	if err != nil {
		return Grants{}, err
	}
	g.mu.Lock()
	if g.grants == nil {
		g.grants = make(map[Scope]Grants, 1)
	}
	g.grants[s] = gr
	g.mu.Unlock()
	return gr, nil
}

// urn is a resource's name: service:region:account:type:path, with the
// region left out for global services and the account for OBS.
func (g *Gate) urn(o *ServiceOptions, s Scope, x Resource) string {
	region, account := s.Region, g.account
	if o.Global {
		region = ""
	}
	if o.NoAccount {
		account = ""
	}
	return strings.Join([]string{o.Name, region, account, x.Type, x.Path}, ":")
}

// keys adds the request's own condition keys to the principal's.
func (g *Gate) keys(principal map[string][]string) map[string][]string {
	k := make(map[string][]string, len(principal)+3)
	for name, v := range principal {
		k[name] = v
	}
	k["g:currenttime"] = []string{g.now.UTC().Format(time.RFC3339)}
	k["g:mfapresent"] = []string{"false"}
	if g.sourceIP != "" {
		k["g:sourceip"] = []string{g.sourceIP}
	}
	return k
}

// explanation is a decoded authorization message. Its outer fields are
// those of Huawei's documented example (sts decode-authorization-message):
// context, user_profile and failure.
type explanation struct {
	Context struct {
		UserProfile struct {
			UserID    string `json:"user_id,omitempty"`
			UserName  string `json:"user_name,omitempty"`
			AccountID string `json:"domain_id,omitempty"`
		} `json:"user_profile"`
		Action    string   `json:"action"`
		Resources []string `json:"resources,omitempty"`
	} `json:"context"`
	Failure   string `json:"failure"`
	Policy    string `json:"policy,omitempty"`
	Statement string `json:"statement,omitempty"`
}

// encode seals the denial's explanation. Without a sealer, or on a
// sealing failure, the denial carries no message.
func (g *Gate) encode(d *Denial) string {
	if g.sealer == nil {
		return ""
	}
	var e explanation
	e.Context.UserProfile.UserID = g.principal.UserID
	e.Context.UserProfile.UserName = g.principal.UserName
	e.Context.UserProfile.AccountID = g.principal.AccountID
	e.Context.Action, e.Context.Resources = d.Action, d.Resources
	e.Failure, e.Policy, e.Statement = d.Decision.Failure(), d.Decision.Policy, d.Decision.Sid
	plain, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	sealed, err := g.sealer.Seal(string(plain), sealLabel)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sealed)
}

// Decode opens an encoded authorization message, as STS
// decode-authorization-message does. ok is false for a message this
// emulator did not issue.
func Decode(s Sealer, encoded string) (plain string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	plain, err = s.Open(raw, sealLabel)
	return plain, err == nil
}
