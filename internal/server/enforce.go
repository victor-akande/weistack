package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

// Enforcement (-iam=enforce): every request to an emulated service must
// carry a valid signature by a known, active key, or a valid IAM token,
// and its caller must be allowed the operation (internal/core/authz):
// after authenticating, the server attaches a gate for the caller, which
// each route consults with its action.
//
// Failures are answered as Huawei's API gateway documents them
// (support.huaweicloud.com/intl/en-us/devg-apisign/api-sign-0001.html and
// api-sign-errorcode.html): 401 with {"error_msg", "error_code",
// "request_id"}.

func (s *Server) enforcing() bool { return s.cfg.IAM == config.IAMEnforce }

// The gateway's errors.
const iamAuthInfo = "Incorrect IAM authentication information: "

var (
	errNoCredentials = apierr.New(http.StatusUnauthorized, "APIGW.0305", "Incorrect authentication information.")
	errBadSignature  = apierr.New(http.StatusUnauthorized, "APIGW.0301", iamAuthInfo+"verify aksk signature fail")
	errLocked        = apierr.New(http.StatusUnauthorized, "APIGW.0301", iamAuthInfo+"AK access failed to reach the limit,forbidden.")
	errBadToken      = apierr.New(http.StatusUnauthorized, "APIGW.0301", iamAuthInfo+"decrypt token fail")
	errTokenExpired  = apierr.New(http.StatusUnauthorized, "APIGW.0307", "The token must be updated.")
)

func errUnknownKey(ak string) *apierr.Error {
	return apierr.New(http.StatusUnauthorized, "APIGW.0301", "%sGet secretKey failed,ak:%s,err:ak not exist", iamAuthInfo, ak)
}

// noCredentialsNeeded are the requests a client makes before it has
// credentials: signing in with a password.
func noCredentialsNeeded(service string, r *http.Request) bool {
	return service == "iam" && r.Method == http.MethodPost && r.URL.Path == "/v3/auth/tokens"
}

// authenticate checks r's credentials in enforce mode. received is the
// URL as the client sent it. It returns the request to serve, carrying
// the verified identity, or writes the error and returns nil.
func (s *Server) authenticate(m *mounted, w http.ResponseWriter, r *http.Request, received *url.URL) *http.Request {
	name := m.svc.Name()
	if name == "obs" {
		return s.authenticateOBS(w, r, received)
	}
	if noCredentialsNeeded(name, r) {
		return r
	}
	id, err := s.verify(m, r, signedPaths(received.Path, r.URL.Path))
	if err != nil {
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "checking credentials", "error", err)
			apiErr = apierr.Internal(err)
		}
		apierr.Write(w, r, apierr.StyleFlatRequestID, apiErr)
		return nil
	}
	return r.WithContext(auth.WithIdentity(r.Context(), id))
}

// gate is the authorization gate for r's authenticated caller.
func (s *Server) gate(r *http.Request) *authz.Gate {
	principal := auth.FromContext(r.Context()).Principal
	account := principal.AccountID
	if account == "" && s.dir != nil {
		account = s.dir.Account().ID
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	o := authz.GateOptions{
		Principal: principal, Account: account,
		Provider: s.perms, Sealer: s.sealer, Log: s.log, Now: s.now(), SourceIP: ip,
	}
	if s.accounts != nil {
		o.ProjectOwner = s.accounts.ProjectOwner
	}
	return authz.NewGate(o)
}

// verify returns the identity r's credentials prove, or the error to
// answer with.
func (s *Server) verify(m *mounted, r *http.Request, paths []string) (auth.Identity, error) {
	id := auth.FromContext(r.Context())
	authz := r.Header.Get("Authorization")
	switch {
	case authz != "":
		return s.verifySignature(m, r, id, authz, paths)
	case r.Header.Get("X-Auth-Token") != "":
		return s.verifyToken(r, id)
	default:
		return id, errNoCredentials
	}
}

func (s *Server) verifyToken(r *http.Request, id auth.Identity) (auth.Identity, error) {
	if s.tokens == nil {
		return id, errBadToken
	}
	p, err := s.tokens.CheckToken(r.Context(), r.Header.Get("X-Auth-Token"))
	switch {
	case errors.Is(err, auth.ErrTokenExpired):
		return id, errTokenExpired
	case errors.Is(err, auth.ErrTokenUnknown):
		return id, errBadToken
	case err != nil:
		return id, err
	}
	id.Known, id.Principal = true, p
	return id, nil
}

func (s *Server) verifySignature(m *mounted, r *http.Request, id auth.Identity, authz string, paths []string) (auth.Identity, error) {
	// Only SDK-HMAC-SHA256 is checked: the SDKs' other algorithms are
	// opt-in, and fail as a signature the gateway cannot verify.
	a, err := sigcheck.ParseSDKHMAC(authz)
	if err != nil {
		return id, errBadSignature
	}
	key, ok := s.credentials(r, a.AccessKey)
	if !ok {
		return id, errUnknownKey(a.AccessKey)
	}
	if key.locked() {
		return id, errLocked
	}
	body, err := signedBody(m, r)
	if err != nil {
		return id, err
	}
	if err := sigcheck.VerifySDKHMAC(r, a, key.secret, body, paths, s.now()); err != nil {
		key.failed()
		return id, errBadSignature
	}
	key.succeeded()
	id.Known, id.Principal, id.Temporary = true, key.principal, key.temporary
	return id, nil
}

// credential is what an access key a request is signed with stands for.
type credential struct {
	s         *Server
	ak        string
	principal identity.Principal
	secret    string
	temporary bool
}

// credentials finds the access key a request is signed with: a
// permanent one, or temporary credentials with the security token r
// carries. ok is false for an unknown key, a disabled user's, and a
// security token that is invalid, expired or not ak's.
func (s *Server) credentials(r *http.Request, ak string) (credential, bool) {
	if p, known := s.dir.Lookup(ak); known {
		secret, has := s.dir.Secret(ak)
		return credential{s: s, ak: ak, principal: p, secret: secret}, has && !p.Disabled
	}
	token := auth.SecurityToken(r)
	if token == "" || s.temporary == nil {
		return credential{}, false
	}
	p, secret, ok := s.temporary.Temporary(r.Context(), ak, token)
	return credential{s: s, ak: ak, principal: p, secret: secret, temporary: true}, ok
}

// Temporary keys are not locked out: each is short-lived, and the
// lockout is the permanent key's.
func (c credential) locked() bool { return !c.temporary && c.s.dir.Locked(c.ak) }

func (c credential) failed() {
	if !c.temporary {
		c.s.dir.SignatureFailed(c.ak)
	}
}

func (c credential) succeeded() {
	if !c.temporary {
		c.s.dir.SignatureSucceeded(c.ak)
	}
}

// signedBody reads the body the signature covers, and puts it back for
// the service. Bodies whose hash the client sent in X-Sdk-Content-Sha256
// are not read.
func signedBody(m *mounted, r *http.Request) ([]byte, error) {
	if r.Header.Get("X-Sdk-Content-Sha256") != "" || r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	limit := m.maxBody
	if limit <= 0 {
		limit = 1 << 30
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading the body to check its signature: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, apierr.New(http.StatusRequestEntityTooLarge, "APIGW.0201", "Request entity too large.")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// signedPaths are the paths a client may have signed: the path as
// received, and, when the service was addressed by a path prefix, the
// path without it, which is what the Go SDK signs.
func signedPaths(received, served string) []string {
	if received == served || served == "" {
		return []string{received}
	}
	return []string{received, served}
}
