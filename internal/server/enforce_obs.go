package server

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

// OBS enforcement: OBS and S3 v2 signatures and S3 signature version 4,
// in a header or a pre-signed URL, and the chunk signatures of
// aws-chunked uploads. Failures are answered with OBS's documented error codes
// (support.huaweicloud.com/intl/en-us/api-obs/obs_04_0115.html), in its
// XML envelope.

var (
	errOBSAnonymous = apierr.New(http.StatusForbidden, "AccessDenied", "Access denied.")
	errOBSNoDate    = apierr.New(http.StatusForbidden, "AccessDenied",
		"Access denied. The request does not include the date header or the header format is incorrect.")
	errOBSExpired      = apierr.New(http.StatusForbidden, "AccessDenied", "Request has expired.")
	errOBSUnknownKey   = apierr.New(http.StatusForbidden, "InvalidAccessKeyId", "The provided access key ID is not found in the system.")
	errOBSBadSignature = apierr.New(http.StatusForbidden, "SignatureDoesNotMatch",
		"The signature included in the request does not match the signature calculated by the system.")
	errOBSSkewed = apierr.New(http.StatusForbidden, "RequestTimeTooSkewed",
		"There is a large difference between the OBS server time and the client's request time.")
	errOBSLocked = apierr.New(http.StatusBadRequest, "TooManyWrongSignature", "The request is rejected due to frequent errors.")
)

// authenticateOBS checks an OBS request's credentials. received is the
// URL as the client sent it, before any /obs prefix was stripped.
func (s *Server) authenticateOBS(w http.ResponseWriter, r *http.Request, received *url.URL) *http.Request {
	ctx := r.Context()
	id, chunks, err := s.verifyOBS(r, received)
	if err != nil {
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(ctx, "checking OBS credentials", "error", err)
			apiErr = apierr.Internal(err)
		}
		apierr.Write(w, r, apierr.StyleXML, apiErr)
		return nil
	}
	ctx = auth.WithIdentity(ctx, id)
	if chunks != nil {
		ctx = sigcheck.WithChunkVerifier(ctx, chunks)
	}
	// A body whose SHA-256 the client declared is checked as OBS reads it.
	if payload := r.Header.Get("X-Amz-Content-Sha256"); sigcheck.SignedPayloadHash(payload) && r.Body != nil && r.Body != http.NoBody {
		r.Body = sigcheck.CheckPayload(r.Body, payload)
	}
	return r.WithContext(ctx)
}

// verifyOBS checks an S3 signature version 4 or a v2 one (OBS or AWS), in
// a header or a pre-signed URL. For an upload of signed chunks it also
// returns the verifier of the chunks.
func (s *Server) verifyOBS(r *http.Request, received *url.URL) (auth.Identity, *sigcheck.ChunkVerifier, error) {
	id := auth.FromContext(r.Context())
	var (
		ak     string
		verify func(secret string) (*sigcheck.ChunkVerifier, error)
	)
	if a4, ok, err := sigcheck.ParseV4(r); ok {
		if err != nil {
			return id, nil, errOBSBadSignature
		}
		ak = a4.AccessKey
		verify = func(secret string) (*sigcheck.ChunkVerifier, error) {
			return sigcheck.VerifyV4(r, a4, secret, obsPaths(r, received), s.now())
		}
	} else if a2, ok, err := sigcheck.ParseV2(r); ok {
		if err != nil {
			return id, nil, errOBSBadSignature
		}
		ak = a2.AccessKey
		verify = func(secret string) (*sigcheck.ChunkVerifier, error) {
			return nil, sigcheck.VerifyV2(r, a2, secret, obsResources(r, received), s.now())
		}
	} else {
		return id, nil, errOBSAnonymous
	}

	key, ok := s.credentials(r, ak)
	if !ok {
		return id, nil, errOBSUnknownKey
	}
	if key.locked() {
		return id, nil, errOBSLocked
	}
	chunks, err := verify(key.secret)
	switch {
	case errors.Is(err, sigcheck.ErrNoDate):
		return id, nil, errOBSNoDate
	case errors.Is(err, sigcheck.ErrExpired):
		return id, nil, errOBSExpired
	case errors.Is(err, sigcheck.ErrSkewed):
		return id, nil, errOBSSkewed
	case err != nil:
		key.failed()
		return id, nil, errOBSBadSignature
	}
	key.succeeded()
	id.AccessKey, id.Known, id.Principal, id.Temporary = ak, true, key.principal, key.temporary
	return id, chunks, nil
}

// obsPaths are the escaped paths an S3 signature version 4 may cover:
// as received, and without an /obs prefix.
func obsPaths(r *http.Request, received *url.URL) []string {
	paths := []string{r.URL.EscapedPath()}
	if raw := received.EscapedPath(); raw != paths[0] {
		paths = append(paths, raw)
	}
	return paths
}

// obsResources are the paths a v2 signature may cover: the escaped path
// as received and as served (without an /obs prefix), each with
// "/bucket" before it for a virtual-hosted request.
func obsResources(r *http.Request, received *url.URL) []string {
	paths := obsPaths(r, received)
	bucket := sigcheck.HostBucketAsSent(r.Host)
	if bucket == "" {
		return paths
	}
	out := make([]string, 0, 2*len(paths))
	for _, p := range paths {
		out = append(out, "/"+bucket+p, p)
	}
	return out
}
