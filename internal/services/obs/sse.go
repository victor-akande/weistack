package obs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/emmansun/gmsm/sm4"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/cmk"
)

// Server-side encryption (api-obs obs_04_0188).
//
// SSE-KMS objects are encrypted at rest: each object (or multipart
// upload) has its own data key from KMS, under the key the request names
// or the account's obs/default key, sealed beside the object. The body
// is encrypted with it in CTR mode (AES-256, or SM4 when
// x-obs-server-side-data-encryption is SM4), so ranges can be read
// without the rest. Downloading asks KMS to open the data key: once the
// key is disabled or deleted, the object cannot be read
// (KMS.DisabledException, KMS.NotFoundException), as on Huawei Cloud.
//
// SSE-OBS (AES256), whose keys OBS manages, is recorded and reported
// but the body is stored as given. SSE-C is not emulated.

// The two algorithms, as each dialect names them.
const (
	sseKMS       = "kms"
	sseKMSS3     = "aws:kms"
	sseOBS       = "AES256"
	sseBucketOBS = "obs" // a bucket's SSE-OBS default, in the OBS dialect
	dataSM4      = "SM4"
	kmsService   = "obs"
)

var (
	errKMSNotFound = apierr.New(http.StatusBadRequest, "KMS.NotFoundException", "The specified KMS master key does not exist.")
	errKMSDisabled = apierr.New(http.StatusBadRequest, "KMS.DisabledException", "The specified KMS master key is disabled.")
	errNoKMS       = errNotImplemented("SSE-KMS without KMS")
)

// sse is how an object, or an upload's parts, are encrypted.
type sse struct {
	// Algorithm is sseKMS or sseOBS.
	Algorithm string `json:"algorithm"`
	// DataAlgorithm is "" (AES-256) or SM4.
	DataAlgorithm string `json:"data_algorithm,omitempty"`
	// KeyURN names the KMS key: <region>:<account-id>:key/<key-id>.
	KeyURN string `json:"kms_key_id,omitempty"`
	// DataKey is the data key, sealed by KMS; IV the body's.
	DataKey []byte `json:"data_key,omitempty"`
	IV      []byte `json:"iv,omitempty"`
}

// encrypted reports whether the body is stored encrypted.
func (e *sse) encrypted() bool { return e != nil && e.Algorithm == sseKMS && len(e.DataKey) > 0 }

// sseRequest is the encryption a request asks for.
type sseRequest struct {
	Algorithm, DataAlgorithm, KeyID string
}

// requestedSSE reads the encryption headers of a write. ok is false when
// it asks for none.
func requestedSSE(c *call) (sseRequest, bool, error) {
	if c.vendorHeader("server-side-encryption-customer-algorithm") != "" {
		return sseRequest{}, false, errNotImplemented("SSE-C (customer-provided keys)")
	}
	alg := c.vendorHeader("server-side-encryption")
	keyID := c.r.Header.Get("x-obs-server-side-encryption-kms-key-id")
	if keyID == "" {
		keyID = c.r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id")
	}
	data := c.r.Header.Get("x-obs-server-side-data-encryption")
	if alg == "" {
		if keyID != "" || data != "" {
			return sseRequest{}, false, errInvalidArgument("the KMS key ID and data encryption headers need x-obs-server-side-encryption")
		}
		return sseRequest{}, false, nil
	}
	switch alg {
	case sseKMS, sseKMSS3:
		alg = sseKMS
	case sseOBS:
		if keyID != "" {
			return sseRequest{}, false, errInvalidArgument("a KMS key ID needs kms server-side encryption")
		}
	default:
		return sseRequest{}, false, errInvalidArgument("server-side encryption must be kms or AES256")
	}
	switch data {
	case "", "AES256":
		data = ""
	case dataSM4:
		if alg != sseKMS {
			return sseRequest{}, false, errInvalidArgument("SM4 data encryption needs kms server-side encryption")
		}
	default:
		return sseRequest{}, false, errInvalidArgument("server-side data encryption must be AES256 or SM4")
	}
	return sseRequest{Algorithm: alg, DataAlgorithm: data, KeyID: keyID}, true, nil
}

// encryptionFor is the encryption of a new object or upload: what the
// request asks for, or else the bucket's default.
func (s *Service) encryptionFor(c *call, b Bucket) (*sse, error) {
	req, ok, err := requestedSSE(c)
	if err != nil {
		return nil, err
	}
	if !ok {
		if b.Encryption == nil {
			return nil, nil
		}
		req = sseRequest{Algorithm: b.Encryption.Algorithm, DataAlgorithm: b.Encryption.DataAlgorithm, KeyID: b.Encryption.KeyID}
	}
	return s.newSSE(c, b.Region, req)
}

// newSSE makes the encryption of new data: a fresh data key for SSE-KMS.
func (s *Service) newSSE(c *call, region string, req sseRequest) (*sse, error) {
	if req.Algorithm != sseKMS {
		return &sse{Algorithm: sseOBS}, nil
	}
	if s.keys == nil {
		return nil, errNoKMS
	}
	dk, err := s.keys.NewDataKey(c.r.Context(), region, req.KeyID, kmsService)
	if err != nil {
		return nil, kmsError(err)
	}
	// Using a key needs the KMS permission too (OBS's dependency on
	// kms:cmk:createDataKey).
	if err := authz.Check(c.r, "kms:cmk:createDataKey", keyResource(dk.KeyURN)); err != nil {
		return nil, err
	}
	iv, err := newIV()
	if err != nil {
		return nil, err
	}
	return &sse{Algorithm: sseKMS, DataAlgorithm: req.DataAlgorithm, KeyURN: dk.KeyURN, DataKey: dk.Sealed, IV: iv}, nil
}

// keyResource is a KMS key's URN, from OBS's <region>:<account>:key/<id>.
func keyResource(urn string) authz.Resource {
	region, rest, _ := strings.Cut(urn, ":")
	account, id, _ := strings.Cut(rest, ":key/")
	return authz.Resource{URN: "kms:" + region + ":" + account + ":KeyId:" + id}
}

func kmsError(err error) error {
	switch {
	case errors.Is(err, cmk.ErrNotFound):
		return errKMSNotFound
	case errors.Is(err, cmk.ErrDisabled):
		return errKMSDisabled
	}
	return err
}

func newIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

// withIV is e with another IV, for one part or a whole object made of
// parts.
func (e *sse) withIV() (*sse, error) {
	if !e.encrypted() {
		return e, nil
	}
	iv, err := newIV()
	if err != nil {
		return nil, err
	}
	out := *e
	out.IV = iv
	return &out, nil
}

// cipherFor opens the data key of e and returns its block cipher.
func (s *Service) cipherFor(c *call, region string, e *sse) (cipher.Block, error) {
	if s.keys == nil {
		return nil, errNoKMS
	}
	key, err := s.keys.OpenDataKey(c.r.Context(), region, e.DataKey)
	if err != nil {
		return nil, kmsError(err)
	}
	if e.DataAlgorithm == dataSM4 {
		return sm4.NewCipher(key[:16])
	}
	return aes.NewCipher(key)
}

// readKey checks the caller may decrypt with an object's key (OBS's
// dependency on kms:cmk:decryptDataKey) and returns its cipher.
func (s *Service) readKey(c *call, region string, e *sse) (cipher.Block, error) {
	if err := authz.Check(c.r, "kms:cmk:decryptDataKey", keyResource(e.KeyURN)); err != nil {
		return nil, err
	}
	return s.cipherFor(c, region, e)
}

// ctrAt is the CTR key stream of block and iv, positioned at off.
func ctrAt(block cipher.Block, iv []byte, off int64) cipher.Stream {
	bs := int64(block.BlockSize())
	counter := new(big.Int).SetBytes(iv)
	counter.Add(counter, big.NewInt(off/bs))
	// Wrap around at the counter's size, as CTR does.
	counter.Mod(counter, new(big.Int).Lsh(big.NewInt(1), uint(8*len(iv))))
	ctr := counter.FillBytes(make([]byte, len(iv)))
	stream := cipher.NewCTR(block, ctr)
	if skip := off % bs; skip > 0 {
		discard := make([]byte, skip)
		stream.XORKeyStream(discard, discard)
	}
	return stream
}

// decryptingReaderAt decrypts a CTR-encrypted body at any offset.
type decryptingReaderAt struct {
	r     io.ReaderAt
	block cipher.Block
	iv    []byte
}

func (d decryptingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := d.r.ReadAt(p, off)
	ctrAt(d.block, d.iv, off).XORKeyStream(p[:n], p[:n])
	return n, err
}

// encrypter returns how a body is written under e: through CTR when it
// is encrypted.
func (s *Service) encrypter(c *call, region string, e *sse) (func(io.Writer) io.Writer, error) {
	if !e.encrypted() {
		return nil, nil
	}
	block, err := s.cipherFor(c, region, e)
	if err != nil {
		return nil, err
	}
	return func(w io.Writer) io.Writer {
		return cipher.StreamWriter{S: ctrAt(block, e.IV, 0), W: w}
	}, nil
}

// plainReader reads a stored body in clear.
func (s *Service) plainReader(c *call, region, blob string, e *sse) (io.ReadCloser, error) {
	f, err := s.blobs.open(blob)
	if err != nil {
		return nil, err
	}
	if !e.encrypted() {
		return f, nil
	}
	block, err := s.cipherFor(c, region, e)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{cipher.StreamReader{S: ctrAt(block, e.IV, 0), R: f}, f}, nil
}

// writeSSEHeaders reports an object's encryption on a response.
func (c *call) writeSSEHeaders(e *sse) {
	if e == nil {
		return
	}
	h := c.w.Header()
	alg := e.Algorithm
	if alg == sseKMS && c.dialect != dialectOBS {
		alg = sseKMSS3
	}
	h.Set(c.dialect.prefix()+"server-side-encryption", alg)
	if e.KeyURN != "" {
		if c.dialect == dialectOBS {
			h.Set("x-obs-server-side-encryption-kms-key-id", e.KeyURN)
		} else {
			h.Set("x-amz-server-side-encryption-aws-kms-key-id", e.KeyURN)
		}
	}
	if e.DataAlgorithm == dataSM4 && c.dialect == dialectOBS {
		h.Set("x-obs-server-side-data-encryption", dataSM4)
	}
}

// ---- Bucket default encryption (?encryption) ----

// bucketSSE is a bucket's default encryption.
type bucketSSE struct {
	Algorithm     string `json:"algorithm"`
	DataAlgorithm string `json:"data_algorithm,omitempty"`
	KeyID         string `json:"kms_key_id,omitempty"`
	ProjectID     string `json:"project_id,omitempty"`
}

type sseConfiguration struct {
	XMLName       xml.Name `xml:"ServerSideEncryptionConfiguration"`
	XMLNS         string   `xml:"xmlns,attr,omitempty"`
	SSEAlgorithm  string   `xml:"Rule>ApplyServerSideEncryptionByDefault>SSEAlgorithm"`
	KMSMasterKey  string   `xml:"Rule>ApplyServerSideEncryptionByDefault>KMSMasterKeyID,omitempty"`
	KMSDataCipher string   `xml:"Rule>ApplyServerSideEncryptionByDefault>KMSDataEncryption,omitempty"`
	ProjectID     string   `xml:"Rule>ApplyServerSideEncryptionByDefault>ProjectID,omitempty"`
}

// handleGetBucketEncryption reports a bucket's default encryption, or
// that it has none, under the code of the request's dialect.
func (s *Service) handleGetBucketEncryption(c *call) error {
	b, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket)
	if err != nil {
		return err
	}
	if b.Encryption == nil {
		if c.dialect != dialectOBS {
			return errNoEncryptionS3
		}
		return errNoEncryptionOBS
	}
	alg := b.Encryption.Algorithm
	if alg == sseKMS && c.dialect != dialectOBS {
		alg = sseKMSS3
	}
	return c.writeXML(sseConfiguration{
		XMLNS: c.dialect.namespace(), SSEAlgorithm: alg, KMSMasterKey: b.Encryption.KeyID,
		KMSDataCipher: b.Encryption.DataAlgorithm, ProjectID: b.Encryption.ProjectID,
	})
}

func (s *Service) handlePutBucketEncryption(c *call) error {
	if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
		return err
	}
	var cfg sseConfiguration
	if err := xml.NewDecoder(io.LimitReader(c.r.Body, maxConfigBody)).Decode(&cfg); err != nil {
		return errMalformedXML
	}
	e := bucketSSE{KeyID: cfg.KMSMasterKey, ProjectID: cfg.ProjectID}
	switch cfg.SSEAlgorithm {
	case sseKMS, sseKMSS3:
		e.Algorithm = sseKMS
	case sseOBS, sseBucketOBS:
		e.Algorithm = sseOBS
		if e.KeyID != "" {
			return errInvalidArgument("a KMS key ID needs kms server-side encryption")
		}
	default:
		return errInvalidArgument("SSEAlgorithm must be kms or AES256")
	}
	switch cfg.KMSDataCipher {
	case "", "AES256":
	case dataSM4:
		e.DataAlgorithm = dataSM4
	default:
		return errInvalidArgument("KMSDataEncryption must be AES256 or SM4")
	}
	if err := s.setBucketEncryption(c, &e); err != nil {
		return err
	}
	c.w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleDeleteBucketEncryption(c *call) error {
	if _, err := s.bucketFor(c.r.Context(), c.owner, c.target.Bucket); err != nil {
		return err
	}
	if err := s.setBucketEncryption(c, nil); err != nil {
		return err
	}
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) setBucketEncryption(c *call, e *bucketSSE) error {
	_, err := s.buckets().Update(c.r.Context(), c.target.Bucket, func(b *Bucket) error {
		b.Encryption = e
		return nil
	})
	if err != nil {
		return fmt.Errorf("obs: setting bucket encryption: %w", err)
	}
	return nil
}
