package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/sigcheck"
)

// OBS enforcement: OBS and S3 v2 signatures, in a header or a pre-signed
// URL. Failures are answered with OBS's documented error codes
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

// signedWithV4 reports a request with an S3 signature version 4, in a
// header or a pre-signed URL. Those are not checked yet.
func signedWithV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") || r.URL.Query().Get("X-Amz-Algorithm") != ""
}

// authenticateOBS checks an OBS request's credentials. received is the
// URL as the client sent it, before any /obs prefix was stripped.
func (s *Server) authenticateOBS(w http.ResponseWriter, r *http.Request, received *url.URL) *http.Request {
	id, err := s.verifyOBS(r, received)
	if err != nil {
		var apiErr *apierr.Error
		if !errors.As(err, &apiErr) {
			s.log.ErrorContext(r.Context(), "checking OBS credentials", "error", err)
			apiErr = apierr.Internal(err)
		}
		apierr.Write(w, r, apierr.StyleXML, apiErr)
		return nil
	}
	return r.WithContext(auth.WithIdentity(r.Context(), id))
}

func (s *Server) verifyOBS(r *http.Request, received *url.URL) (auth.Identity, error) {
	id := auth.FromContext(r.Context())
	a, signed, err := sigcheck.ParseV2(r)
	switch {
	case err != nil:
		return id, errOBSBadSignature
	case !signed && signedWithV4(r):
		return id, nil // checked from a later release
	case !signed:
		return id, errOBSAnonymous
	}
	p, known := s.dir.Lookup(a.AccessKey)
	secret, hasSecret := s.dir.Secret(a.AccessKey)
	if !known || !hasSecret || p.Disabled {
		return id, errOBSUnknownKey
	}
	if s.dir.Locked(a.AccessKey) {
		return id, errOBSLocked
	}
	err = sigcheck.VerifyV2(r, a, secret, obsResources(r, received), s.now())
	switch {
	case errors.Is(err, sigcheck.ErrNoDate):
		return id, errOBSNoDate
	case errors.Is(err, sigcheck.ErrExpired):
		return id, errOBSExpired
	case errors.Is(err, sigcheck.ErrSkewed):
		return id, errOBSSkewed
	case err != nil:
		s.dir.SignatureFailed(a.AccessKey)
		return id, errOBSBadSignature
	}
	s.dir.SignatureSucceeded(a.AccessKey)
	id.AccessKey, id.Known, id.Principal = a.AccessKey, true, p
	return id, nil
}

// obsResources are the paths a v2 signature may cover: the escaped path
// as received and as served (without an /obs prefix), each with
// "/bucket" before it for a virtual-hosted request.
func obsResources(r *http.Request, received *url.URL) []string {
	paths := []string{r.URL.EscapedPath()}
	if raw := received.EscapedPath(); raw != paths[0] {
		paths = append(paths, raw)
	}
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
