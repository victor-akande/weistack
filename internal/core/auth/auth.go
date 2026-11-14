// Package auth identifies the caller of a request.
//
// In the MVP the emulator runs in "accept" mode: any access key, any
// signature and any token are allowed. The credentials are still parsed
// so the hook is live and so logs show who a client claims to be;
// signature verification will slot in here later.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/victor-akande/weistack/internal/core/identity"
)

// Authorization schemes the emulator recognises.
const (
	// SchemeSDKHMAC is Huawei's API gateway signing, used by the SDKs,
	// KooCLI and Terraform: "SDK-HMAC-SHA256 Access=AK, SignedHeaders=..., Signature=...".
	SchemeSDKHMAC = "SDK-HMAC-SHA256"
	// SchemeOBS is OBS header signing: "OBS AK:signature".
	SchemeOBS = "OBS"
	// SchemeAWSV2 is S3 signature version 2: "AWS AK:signature".
	SchemeAWSV2 = "AWS"
	// SchemeAWSV4 is S3 signature version 4:
	// "AWS4-HMAC-SHA256 Credential=AK/date/region/s3/aws4_request, ...".
	SchemeAWSV4 = "AWS4-HMAC-SHA256"
	// SchemeToken means the request carried an IAM token in X-Auth-Token.
	SchemeToken = "token"
	// SchemeNone means the request carried no credentials.
	SchemeNone = "none"
)

// Identity is what a request claims about its caller. It never holds a
// secret: signatures and tokens are deliberately dropped.
type Identity struct {
	// Scheme is one of the Scheme constants, or the raw scheme word for
	// an Authorization header the emulator does not recognise.
	Scheme string
	// AccessKey is the AK the request was signed with, if any.
	AccessKey string
	// ProjectID is the X-Project-Id header, if sent.
	ProjectID string
	// HasToken reports whether X-Auth-Token was present.
	HasToken bool
	// Temporary reports whether a security token for temporary
	// credentials (X-Security-Token) was present.
	Temporary bool
	// Known reports whether WeiStack knows the access key, and Principal
	// is then who it belongs to. Unknown keys are accepted as in v0.1.
	Known     bool
	Principal identity.Principal
}

// AccountOwnerPrefix marks an owner that is an account rather than a raw
// access key. Access keys cannot contain ":", so the two never collide.
const AccountOwnerPrefix = "domain:"

// Owner returns who owns what the caller creates. A known key acts for
// its account, as on Huawei Cloud. Any other key is, as in v0.1, an
// owner of its own. Empty means the request named no access key.
func (id Identity) Owner() string {
	if id.Known {
		return AccountOwnerPrefix + id.Principal.AccountID
	}
	return id.AccessKey
}

// Resolver finds who an access key belongs to.
type Resolver interface {
	Lookup(accessKey string) (identity.Principal, bool)
}

// UsageRecorder is implemented by a Resolver that remembers when each
// known key was last used.
type UsageRecorder interface {
	KeyUsed(accessKey string)
}

// Resolve completes id with what resolver knows about its access key. A
// known key is reported as used, if the resolver records usage.
func Resolve(id Identity, resolver Resolver) Identity {
	if resolver == nil || id.AccessKey == "" {
		return id
	}
	if p, ok := resolver.Lookup(id.AccessKey); ok {
		id.Known, id.Principal = true, p
		if rec, ok := resolver.(UsageRecorder); ok {
			rec.KeyUsed(id.AccessKey)
		}
	}
	return id
}

// Parse extracts the Identity from request headers. It never fails:
// malformed credentials yield an Identity with as much as could be read.
func Parse(h http.Header) Identity {
	id := Identity{
		Scheme:    SchemeNone,
		ProjectID: h.Get("X-Project-Id"),
		HasToken:  h.Get("X-Auth-Token") != "",
		Temporary: h.Get("X-Security-Token") != "" || h.Get("X-Obs-Security-Token") != "" || h.Get("X-Amz-Security-Token") != "",
	}
	if id.HasToken {
		id.Scheme = SchemeToken
	}

	authz := strings.TrimSpace(h.Get("Authorization"))
	if authz == "" {
		return id
	}
	scheme, rest, _ := strings.Cut(authz, " ")
	rest = strings.TrimSpace(rest)
	id.Scheme = scheme

	switch scheme {
	case SchemeSDKHMAC:
		id.AccessKey = param(rest, "Access")
	case SchemeAWSV4:
		// Credential is "AK/date/region/service/aws4_request".
		id.AccessKey, _, _ = strings.Cut(param(rest, "Credential"), "/")
	case SchemeOBS, SchemeAWSV2:
		id.AccessKey, _, _ = strings.Cut(rest, ":")
	}
	return id
}

// param finds "name=value" in a comma-separated parameter list.
func param(list, name string) string {
	for _, part := range strings.Split(list, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && k == name {
			return v
		}
	}
	return ""
}

type ctxKey struct{}

// WithIdentity returns a copy of ctx carrying id.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

type resolverKey struct{}

// ResolverFromContext returns the Resolver Middleware used, so a service
// can resolve a key the request carries elsewhere, such as the access key
// of a presigned URL.
func ResolverFromContext(ctx context.Context) Resolver {
	r, _ := ctx.Value(resolverKey{}).(Resolver)
	return r
}

// FromContext returns the Identity stored by Middleware, or the zero
// Identity with SchemeNone.
func FromContext(ctx context.Context) Identity {
	if id, ok := ctx.Value(ctxKey{}).(Identity); ok {
		return id
	}
	return Identity{Scheme: SchemeNone}
}

// Middleware parses credentials, resolves the access key with resolver
// (which may be nil), stores the Identity in the request context and logs
// it at debug level. In accept mode it never rejects.
func Middleware(log *slog.Logger, resolver Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := Resolve(Parse(r.Header), resolver)
			log.DebugContext(r.Context(), "auth accepted",
				"scheme", id.Scheme,
				"access_key", id.AccessKey,
				"known", id.Known,
				"account", id.Principal.AccountID,
				"project_id", id.ProjectID,
				"has_token", id.HasToken,
				"temporary", id.Temporary,
			)
			ctx := WithIdentity(r.Context(), id)
			if resolver != nil {
				ctx = context.WithValue(ctx, resolverKey{}, resolver)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TokenChecker validates IAM tokens (X-Auth-Token) for enforcement.
type TokenChecker interface {
	// CheckToken returns the principal a token acts as, or
	// ErrTokenUnknown or ErrTokenExpired.
	CheckToken(ctx context.Context, token string) (identity.Principal, error)
}

// Token errors.
var (
	// ErrTokenUnknown is a token WeiStack did not issue, or one that has
	// ended (its user was deleted or disabled, or changed password).
	ErrTokenUnknown = errors.New("auth: unknown token")
	// ErrTokenExpired is a token past its expiry.
	ErrTokenExpired = errors.New("auth: token expired")
)
