package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"hash"
	"net/http"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// Asymmetric keys and MACs (api-dew "Signature Verification",
// "Asymmetric Encryption", "MAC"): signing and verifying with RSA, EC,
// secp256k1, SM2 and Ed25519 keys; encrypting with RSA (OAEP SHA-256)
// and SM2 keys; the public key in PEM; HMACs.

var (
	errAsymmetricAlg = kmsErr(http.StatusBadRequest, "KMS.2106", "The rsa key not support this encryption algorithm.")
	errSM2Alg        = kmsErr(http.StatusBadRequest, "KMS.2107", "The sm2 key not support this encryption algorithm.")
	errRSAPlainLong  = kmsErr(http.StatusBadRequest, "KMS.2108", "The rsa encryption plain_text is over length.")
	errECEncrypt     = kmsErr(http.StatusBadRequest, "KMS.1114", "EC keys do not support to encrypt/decrypt.")
	errSymmetricSign = kmsErr(http.StatusBadRequest, "KMS.1115", "Symmetric keys do not support to sign/verify.")
	errDigestLength  = kmsErr(http.StatusBadRequest, "KMS.0329", "Hash algorithm does not match the digest length.")
	errSigningAlg    = kmsErr(http.StatusBadRequest, "KMS.0332", "This key is not support the signing algorithm.")
	errSM2Raw        = kmsErr(http.StatusBadRequest, "KMS.0333", "The signing algorithm SM2DSA_SM3 not support RAW signing.")
	errForEncrypt    = kmsErr(http.StatusBadRequest, "KMS.0334", "The cmk is used to encrypt and decrypt.")
	errSymmetricOp   = kmsErr(http.StatusBadRequest, "KMS.0331", "The symmetric key is not support this operation.")
)

const (
	algRSAOAEP = "RSAES_OAEP_SHA_256"
	algSM2     = "SM2_ENCRYPT"
)

// privateKey opens an asymmetric key's current material.
func (s *Service) privateKey(k key) (any, error) {
	raw, err := s.material(k, len(k.Materials)-1)
	if err != nil {
		return nil, err
	}
	switch k.Spec {
	case specSM2:
		return sm2.NewPrivateKey(raw)
	case specSECP256K1:
		return secp256k1.PrivKeyFromBytes(raw), nil
	}
	return x509.ParsePKCS8PrivateKey(raw)
}

// Curve OIDs for the public keys the standard library cannot marshal.
var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSM2         = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// publicKeyDER is a key's SubjectPublicKeyInfo.
func publicKeyDER(priv any) ([]byte, error) {
	var (
		curve asn1.ObjectIdentifier
		point []byte
	)
	switch p := priv.(type) {
	case *sm2.PrivateKey:
		curve, point = oidSM2, elliptic.Marshal(p.Curve, p.X, p.Y) //nolint:staticcheck // SM2 points are not crypto/ecdh's
	case *secp256k1.PrivateKey:
		curve, point = oidSecp256k1, p.PubKey().SerializeUncompressed()
	case crypto.Signer:
		return x509.MarshalPKIXPublicKey(p.Public())
	default:
		return nil, errors.New("kms: no public key")
	}
	params, err := asn1.Marshal(curve)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}{oidECPublicKey, asn1.RawValue{FullBytes: params}},
		PublicKey: asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
}

// forAsymmetric checks a key is an enabled asymmetric key of the usage.
func forAsymmetric(k key, usage string) error {
	if err := usable(k); err != nil {
		return err
	}
	switch {
	case specs[k.Spec] == symmetric && usage == usageSign:
		return errSymmetricSign
	case specs[k.Spec] != asymmetric:
		return errSymmetricOp
	case k.Usage != usage && usage == usageSign:
		return errForEncrypt
	case k.Usage != usage:
		return errForSign
	}
	return nil
}

func (s *Service) handlePublicKey(w http.ResponseWriter, _ *http.Request, _ tenant, k key) error {
	if specs[k.Spec] != asymmetric {
		return errSymmetricOp
	}
	if err := usable(k); err != nil {
		return err
	}
	priv, err := s.privateKey(k)
	if err != nil {
		return err
	}
	der, err := publicKeyDER(priv)
	if err != nil {
		return err
	}
	// The example answers PEM with CRLF line ends.
	p := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "\n", "\r\n")
	return write(w, struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}{k.ID, p})
}

// Signing algorithms and their hashes.
var signingHashes = map[string]crypto.Hash{
	"RSASSA_PSS_SHA_256": crypto.SHA256, "RSASSA_PSS_SHA_384": crypto.SHA384, "RSASSA_PSS_SHA_512": crypto.SHA512,
	"RSASSA_PKCS1_V1_5_SHA_256": crypto.SHA256, "RSASSA_PKCS1_V1_5_SHA_384": crypto.SHA384, "RSASSA_PKCS1_V1_5_SHA_512": crypto.SHA512,
	"ECDSA_SHA_256": crypto.SHA256, "ECDSA_SHA_384": crypto.SHA384, "ECDSA_SHA_512": crypto.SHA512,
	"SM2DSA_SM3": 0, "ED25519_SHA_512": crypto.SHA512, "ED25519_PH_SHA_512": crypto.SHA512,
}

// algorithmFits reports whether a key spec signs with an algorithm.
func algorithmFits(spec, alg string) bool {
	switch spec {
	case specRSA2048, specRSA3072, specRSA4096:
		return strings.HasPrefix(alg, "RSASSA_")
	case specECP256, specECP384, specSECP256K1:
		return strings.HasPrefix(alg, "ECDSA_")
	case specSM2:
		return alg == "SM2DSA_SM3"
	case specED25519:
		return strings.HasPrefix(alg, "ED25519_")
	}
	return false
}

type signRequest struct {
	KeyID            string `json:"key_id"`
	Message          string `json:"message"`
	Signature        string `json:"signature"`
	SigningAlgorithm string `json:"signing_algorithm"`
	MessageType      string `json:"message_type"`
}

// maxMessage bounds sign's message, before Base64.
const maxMessage = 4096

// signInput is what a signing algorithm signs: the digest (a DIGEST
// message, or the hash of a RAW one), or the message itself for pure
// Ed25519.
func signInput(spec string, b signRequest) ([]byte, error) {
	msg, err := decodeBase64(b.Message)
	if err != nil || len(msg) == 0 || len(msg) > maxMessage {
		return nil, errParam
	}
	h, ok := signingHashes[b.SigningAlgorithm]
	if !ok || !algorithmFits(spec, b.SigningAlgorithm) {
		return nil, errSigningAlg
	}
	raw := b.MessageType == "RAW"
	switch {
	case b.MessageType != "" && b.MessageType != "RAW" && b.MessageType != "DIGEST":
		return nil, errParam
	case b.SigningAlgorithm == "SM2DSA_SM3":
		if raw {
			return nil, errSM2Raw
		}
		if len(msg) != sm3.Size {
			return nil, errDigestLength
		}
		return msg, nil
	case b.SigningAlgorithm == "ED25519_SHA_512":
		// Pure Ed25519 signs the message, not a digest of it.
		if !raw {
			return nil, errParam
		}
		return msg, nil
	}
	if raw {
		d := h.New()
		d.Write(msg)
		return d.Sum(nil), nil
	}
	if len(msg) != h.Size() {
		return nil, errDigestLength
	}
	return msg, nil
}

func sign(priv any, alg string, in []byte) ([]byte, error) {
	h := signingHashes[alg]
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if strings.HasPrefix(alg, "RSASSA_PSS_") {
			return rsa.SignPSS(rand.Reader, p, h, in, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.SignPKCS1v15(rand.Reader, p, h, in)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, p, in)
	case *secp256k1.PrivateKey:
		return secpecdsa.Sign(p, in).Serialize(), nil
	case *sm2.PrivateKey:
		return sm2.SignASN1(rand.Reader, p, in, nil)
	case ed25519.PrivateKey:
		if alg == "ED25519_PH_SHA_512" {
			return p.Sign(nil, in, &ed25519.Options{Hash: crypto.SHA512})
		}
		return ed25519.Sign(p, in), nil
	}
	return nil, errors.New("kms: not a signing key")
}

func verify(priv any, alg string, in, sig []byte) bool {
	h := signingHashes[alg]
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if strings.HasPrefix(alg, "RSASSA_PSS_") {
			return rsa.VerifyPSS(&p.PublicKey, h, in, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) == nil
		}
		return rsa.VerifyPKCS1v15(&p.PublicKey, h, in, sig) == nil
	case *ecdsa.PrivateKey:
		return ecdsa.VerifyASN1(&p.PublicKey, in, sig)
	case *secp256k1.PrivateKey:
		parsed, err := secpecdsa.ParseDERSignature(sig)
		return err == nil && parsed.Verify(in, p.PubKey())
	case *sm2.PrivateKey:
		return sm2.VerifyASN1(&p.PublicKey, in, sig)
	case ed25519.PrivateKey:
		pub := p.Public().(ed25519.PublicKey)
		if alg == "ED25519_PH_SHA_512" {
			return ed25519.VerifyWithOptions(pub, in, sig, &ed25519.Options{Hash: crypto.SHA512}) == nil
		}
		return ed25519.Verify(pub, in, sig)
	}
	return false
}

// signing reads a sign or verify request and finds what it signs with.
func (s *Service) signing(r *http.Request, t tenant, action string) (signRequest, key, any, []byte, error) {
	var b signRequest
	if err := decode(r, &b); err != nil {
		return b, key{}, nil, nil, err
	}
	k, err := s.authorized(r, t, action, b.KeyID)
	if err != nil {
		return b, key{}, nil, nil, err
	}
	if b.Message == "" || b.SigningAlgorithm == "" {
		return b, key{}, nil, nil, errMissing
	}
	if err := forAsymmetric(k, usageSign); err != nil {
		return b, key{}, nil, nil, err
	}
	in, err := signInput(k.Spec, b)
	if err != nil {
		return b, key{}, nil, nil, err
	}
	priv, err := s.privateKey(k)
	return b, k, priv, in, err
}

func (s *Service) handleSign(w http.ResponseWriter, r *http.Request, t tenant) error {
	b, k, priv, in, err := s.signing(r, t, "kms:cmk:sign")
	if err != nil {
		return err
	}
	sig, err := sign(priv, b.SigningAlgorithm, in)
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}{k.ID, encodeBase64(sig)})
}

func (s *Service) handleVerify(w http.ResponseWriter, r *http.Request, t tenant) error {
	b, k, priv, in, err := s.signing(r, t, "kms:cmk:verify")
	if err != nil {
		return err
	}
	sig, err := decodeBase64(b.Signature)
	if err != nil || len(sig) == 0 {
		return errParam
	}
	valid := "false"
	if verify(priv, b.SigningAlgorithm, in, sig) {
		valid = "true"
	}
	return write(w, struct {
		KeyID          string `json:"key_id"`
		SignatureValid string `json:"signature_valid"`
	}{k.ID, valid})
}

// encryptAsymmetric encrypts with an RSA or SM2 key's public key.
func encryptAsymmetric(priv any, alg string, plain []byte) ([]byte, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if alg != algRSAOAEP {
			return nil, errAsymmetricAlg
		}
		if len(plain) > p.Size()-2*sha256.Size-2 {
			return nil, errRSAPlainLong
		}
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, &p.PublicKey, plain, nil)
	case *sm2.PrivateKey:
		if alg != algSM2 {
			return nil, errSM2Alg
		}
		return sm2.EncryptASN1(rand.Reader, &p.PublicKey, plain)
	}
	return nil, errECEncrypt
}

func decryptAsymmetric(priv any, alg string, ct []byte) ([]byte, error) {
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if alg != algRSAOAEP {
			return nil, errAsymmetricAlg
		}
		out, err := rsa.DecryptOAEP(sha256.New(), nil, p, ct, nil)
		if err != nil {
			return nil, errCipherText
		}
		return out, nil
	case *sm2.PrivateKey:
		if alg != algSM2 {
			return nil, errSM2Alg
		}
		out, err := sm2.Decrypt(p, ct)
		if err != nil {
			return nil, errCipherText
		}
		return out, nil
	}
	return nil, errECEncrypt
}

// forAsymmetricEncryption checks a key can encrypt with its public key.
func forAsymmetricEncryption(k key) error {
	switch k.Spec {
	case specECP256, specECP384, specSECP256K1, specED25519:
		return errECEncrypt
	}
	return forAsymmetric(k, usageEncrypt)
}

// MACs.

var macAlgorithms = map[string]string{
	"HMAC_SHA_256": specHMAC256, "HMAC_SHA_384": specHMAC384, "HMAC_SHA_512": specHMAC512, "HMAC_SM3": specHMACSM3,
}

type macRequest struct {
	KeyID        string `json:"key_id"`
	MacAlgorithm string `json:"mac_algorithm"`
	Message      string `json:"message"`
	Mac          string `json:"mac"`
}

// macOf computes a message's MAC with a key, checking the request.
func (s *Service) macOf(r *http.Request, t tenant, action string) (macRequest, key, []byte, error) {
	var b macRequest
	if err := decode(r, &b); err != nil {
		return b, key{}, nil, err
	}
	k, err := s.authorized(r, t, action, b.KeyID)
	if err != nil {
		return b, key{}, nil, err
	}
	if b.Message == "" || b.MacAlgorithm == "" {
		return b, key{}, nil, errMissing
	}
	if err := usable(k); err != nil {
		return b, key{}, nil, err
	}
	spec, ok := macAlgorithms[b.MacAlgorithm]
	if !ok || k.Usage != usageMAC || spec != k.Spec {
		return b, key{}, nil, errParam
	}
	msg, err := decodeBase64(b.Message)
	if err != nil || len(msg) == 0 || len(msg) > maxMessage {
		return b, key{}, nil, errParam
	}
	m, err := s.material(k, len(k.Materials)-1)
	if err != nil {
		return b, key{}, nil, err
	}
	var newHash func() hash.Hash
	switch spec {
	case specHMAC256:
		newHash = sha256.New
	case specHMAC384:
		newHash = sha512.New384
	case specHMAC512:
		newHash = sha512.New
	default:
		newHash = sm3.New
	}
	mac := hmac.New(newHash, m)
	mac.Write(msg)
	return b, k, mac.Sum(nil), nil
}

func (s *Service) handleGenerateMac(w http.ResponseWriter, r *http.Request, t tenant) error {
	b, k, mac, err := s.macOf(r, t, "kms:cmk:generateMac")
	if err != nil {
		return err
	}
	return write(w, struct {
		KeyID        string `json:"key_id"`
		MacAlgorithm string `json:"mac_algorithm"`
		Mac          string `json:"mac"`
	}{k.ID, b.MacAlgorithm, hexLower(mac)})
}

func (s *Service) handleVerifyMac(w http.ResponseWriter, r *http.Request, t tenant) error {
	b, k, mac, err := s.macOf(r, t, "kms:cmk:verifyMac")
	if err != nil {
		return err
	}
	if b.Mac == "" {
		return errMissing
	}
	return write(w, struct {
		KeyID        string `json:"key_id"`
		MacAlgorithm string `json:"mac_algorithm"`
		MacValid     bool   `json:"mac_valid"`
	}{k.ID, b.MacAlgorithm, hmac.Equal([]byte(strings.ToLower(b.Mac)), []byte(hexLower(mac)))})
}
