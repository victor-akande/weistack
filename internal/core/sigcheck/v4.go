package sigcheck

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// S3 signature version 4, in an Authorization header or a pre-signed URL,
// as aws-sdk-go-v2 v1.48.0 (aws/signer/v4) and the OBS SDK's v4 mode
// (authV4.go) sign it, for service "s3". For S3 the canonical URI is the
// path as sent: it is not escaped again.

// V4 is the algorithm's name.
const V4 = "AWS4-HMAC-SHA256"

const (
	amzDateFormat = "20060102T150405Z"
	// maxPresignExpiry is S3's limit on X-Amz-Expires: seven days.
	maxPresignExpiry = 7 * 24 * time.Hour
	// streamingSigned is the payload of an aws-chunked body whose chunks
	// are signed.
	streamingSigned = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	emptySHA256     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// V4Auth is a parsed SigV4 signature.
type V4Auth struct {
	AccessKey     string
	Date          string // yyyymmdd of the credential scope
	Region        string
	Service       string
	SignedHeaders []string
	Signature     string
	// Presigned marks a signature in the query, valid for Expires from
	// X-Amz-Date.
	Presigned bool
	Expires   time.Duration
}

// scope is "date/region/service/aws4_request".
func (a V4Auth) scope() string { return a.Date + "/" + a.Region + "/" + a.Service + "/aws4_request" }

// ParseV4 finds a SigV4 signature in r: the Authorization header, or the
// query of a pre-signed URL. ok is false if r carries neither.
func ParseV4(r *http.Request) (a V4Auth, ok bool, err error) {
	if authz := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(authz, V4+" ") {
		var credential, signed string
		for part := range strings.SplitSeq(strings.TrimPrefix(authz, V4+" "), ",") {
			k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch k {
			case "Credential":
				credential = v
			case "SignedHeaders":
				signed = v
			case "Signature":
				a.Signature = v
			}
		}
		return finishV4(a, credential, signed)
	}
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") == "" {
		return V4Auth{}, false, nil
	}
	if q.Get("X-Amz-Algorithm") != V4 {
		return V4Auth{}, true, ErrMalformed
	}
	a.Presigned = true
	a.Signature = q.Get("X-Amz-Signature")
	secs, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || secs < 1 || time.Duration(secs)*time.Second > maxPresignExpiry {
		return V4Auth{}, true, ErrMalformed
	}
	a.Expires = time.Duration(secs) * time.Second
	return finishV4(a, q.Get("X-Amz-Credential"), q.Get("X-Amz-SignedHeaders"))
}

// finishV4 reads "AK/date/region/service/aws4_request" and the signed
// header list.
func finishV4(a V4Auth, credential, signed string) (V4Auth, bool, error) {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" || parts[0] == "" || signed == "" || a.Signature == "" {
		return V4Auth{}, true, ErrMalformed
	}
	a.AccessKey, a.Date, a.Region, a.Service = parts[0], parts[1], parts[2], parts[3]
	a.SignedHeaders = strings.Split(signed, ";")
	return a, true, nil
}

// signingTime is the request's time: X-Amz-Date (header or query), or
// the Date header, which the OBS SDK signs instead.
func signingTime(r *http.Request, a V4Auth) (string, time.Time, error) {
	amzDate := r.Header.Get("X-Amz-Date")
	if a.Presigned {
		amzDate = r.URL.Query().Get("X-Amz-Date")
	}
	if amzDate != "" {
		t, err := time.Parse(amzDateFormat, amzDate)
		if err != nil {
			return "", time.Time{}, ErrMalformed
		}
		return amzDate, t, nil
	}
	if date := r.Header.Get("Date"); date != "" {
		t, err := http.ParseTime(date)
		if err != nil {
			return "", time.Time{}, ErrNoDate
		}
		return t.UTC().Format(amzDateFormat), t, nil
	}
	return "", time.Time{}, ErrNoDate
}

// ChunkVerifier checks the signatures of an aws-chunked body, chunk by
// chunk, each chained to the one before.
type ChunkVerifier struct {
	key   []byte
	date  string
	scope string
	prev  string
}

// NewChunkVerifier returns the verifier of a body's chunks signed with
// secret, at amzDate (yyyymmddThhmmssZ), in region and service, chained
// from the request's own signature, seed.
func NewChunkVerifier(secret, amzDate, region, service, seed string) *ChunkVerifier {
	date := amzDate[:min(8, len(amzDate))]
	return &ChunkVerifier{
		key: deriveV4Key(secret, date, region, service), date: amzDate,
		scope: date + "/" + region + "/" + service + "/aws4_request", prev: seed,
	}
}

// Check verifies the signature of the next chunk, given its data's
// SHA-256.
func (c *ChunkVerifier) Check(signature string, dataSHA256 []byte) error {
	toSign := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.date + "\n" + c.scope + "\n" + c.prev + "\n" + emptySHA256 + "\n" +
		hex.EncodeToString(dataSHA256)
	want := hex.EncodeToString(hmacSHA256(c.key, toSign))
	if subtle.ConstantTimeCompare([]byte(want), []byte(signature)) != 1 {
		return ErrChunk
	}
	c.prev = signature
	return nil
}

type chunkKey struct{}

// WithChunkVerifier attaches a ChunkVerifier for the request's body.
func WithChunkVerifier(ctx context.Context, v *ChunkVerifier) context.Context {
	return context.WithValue(ctx, chunkKey{}, v)
}

// ChunkVerifierFrom returns the request's ChunkVerifier, or nil when its
// chunks are not to be checked.
func ChunkVerifierFrom(ctx context.Context) *ChunkVerifier {
	v, _ := ctx.Value(chunkKey{}).(*ChunkVerifier)
	return v
}

// VerifyV4 checks a SigV4 signature with secret. paths are the escaped
// paths the client may have signed. Header-signed requests must be dated
// within MaxSkew of now; pre-signed ones must not have expired. For a
// body of signed chunks it returns the verifier of their signatures.
func VerifyV4(r *http.Request, a V4Auth, secret string, paths []string, now time.Time) (*ChunkVerifier, error) {
	amzDate, t, err := signingTime(r, a)
	if err != nil {
		return nil, err
	}
	if t.UTC().Format("20060102") != a.Date {
		return nil, ErrMismatch
	}
	switch {
	case a.Presigned && !now.Before(t.Add(a.Expires)):
		return nil, ErrExpired
	case !a.Presigned:
		if d := now.Sub(t); d > MaxSkew || d < -MaxSkew {
			return nil, ErrSkewed
		}
	}
	want, err := hex.DecodeString(a.Signature)
	if err != nil {
		return nil, ErrMalformed
	}
	payload := "UNSIGNED-PAYLOAD"
	if !a.Presigned {
		payload = r.Header.Get("X-Amz-Content-Sha256")
		if payload == "" {
			payload = emptySHA256
		}
	}
	key := deriveV4Key(secret, a.Date, a.Region, a.Service)
	query := v4Query(r.URL.RawQuery, a.Presigned)
	signed := strings.Join(a.SignedHeaders, ";")
	for _, host := range v4Hosts(r.Host) {
		headers := v4Headers(r, a.SignedHeaders, host)
		for _, p := range paths {
			canonical := strings.Join([]string{r.Method, p, query, headers, signed, payload}, "\n")
			crHash := sha256.Sum256([]byte(canonical))
			toSign := V4 + "\n" + amzDate + "\n" + a.scope() + "\n" + hex.EncodeToString(crHash[:])
			if subtle.ConstantTimeCompare(hmacSHA256(key, toSign), want) == 1 {
				if payload == streamingSigned {
					return &ChunkVerifier{key: key, date: amzDate, scope: a.scope(), prev: a.Signature}, nil
				}
				return nil, nil
			}
		}
	}
	return nil, ErrMismatch
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func deriveV4Key(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// v4Hosts are the hosts a client may have signed: as received, and
// without a default port, which the SDKs drop before signing.
func v4Hosts(host string) []string {
	h, port, err := net.SplitHostPort(host)
	if err == nil && (port == "80" || port == "443") {
		return []string{h, host}
	}
	return []string{host}
}

// v4Headers writes "name:value\n" for each signed header: values with
// spaces trimmed and runs of spaces collapsed, joined with ",". host is
// the request's host, content-length its length.
func v4Headers(r *http.Request, signed []string, host string) string {
	var b strings.Builder
	for _, name := range signed {
		var values []string
		switch name {
		case "host":
			values = []string{host}
		case "content-length":
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		default:
			values = r.Header.Values(name)
		}
		for i, v := range values {
			values[i] = collapseSpaces(strings.TrimSpace(v))
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(values, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

func collapseSpaces(s string) string {
	if !strings.Contains(s, "  ") {
		return s
	}
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == ' ' }), " ")
}

// v4Query sorts the query by key, then value, both URI-encoded; a
// pre-signed URL's own signature is left out.
func v4Query(raw string, presigned bool) string {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	type pair struct{ k, v string }
	var pairs []pair
	for k, vs := range q {
		if presigned && k == "X-Amz-Signature" {
			continue
		}
		for _, v := range vs {
			pairs = append(pairs, pair{uriEncode(k), uriEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// uriEncode percent-encodes everything but A-Z a-z 0-9 - _ . ~, as
// SigV4 requires; it is the same set as the API gateway's escape.
func uriEncode(s string) string { return escape(s) }

// ErrChunk is a chunk whose signature does not match.
var ErrChunk = errors.New("sigcheck: chunk signature does not match")
