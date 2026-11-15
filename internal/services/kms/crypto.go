package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// Key specs (create-key's key_spec) and usages.
const (
	specAES256    = "AES_256"
	specSM4       = "SM4"
	specRSA2048   = "RSA_2048"
	specRSA3072   = "RSA_3072"
	specRSA4096   = "RSA_4096"
	specECP256    = "EC_P256"
	specECP384    = "EC_P384"
	specSECP256K1 = "SECP256K1"
	specSM2       = "SM2"
	specED25519   = "ED25519"
	specHMAC256   = "HMAC_256"
	specHMAC384   = "HMAC_384"
	specHMAC512   = "HMAC_512"
	specHMACSM3   = "HMAC_SM3"

	usageEncrypt = "ENCRYPT_DECRYPT"
	usageSign    = "SIGN_VERIFY"
	// usageMAC is the usage KMS reports for HMAC keys, which create-key
	// does not take.
	usageMAC = "GENERATE_VERIFY_MAC"
)

// specs are the key specs and their kinds.
var specs = map[string]specKind{
	specAES256: symmetric, specSM4: symmetric,
	specRSA2048: asymmetric, specRSA3072: asymmetric, specRSA4096: asymmetric,
	specECP256: asymmetric, specECP384: asymmetric, specSECP256K1: asymmetric,
	specSM2: asymmetric, specED25519: asymmetric,
	specHMAC256: mac, specHMAC384: mac, specHMAC512: mac, specHMACSM3: mac,
}

type specKind int

const (
	symmetric specKind = iota
	asymmetric
	mac
)

// defaultUsage is a spec's usage when create-key gives none.
func defaultUsage(spec string) string {
	switch specs[spec] {
	case asymmetric:
		return usageSign
	case mac:
		return usageMAC
	}
	return usageEncrypt
}

// usageAllowed reports whether a spec can have a usage: symmetric keys
// encrypt, EC and Ed25519 keys sign, RSA and SM2 keys do either.
func usageAllowed(spec, usage string) bool {
	switch spec {
	case specRSA2048, specRSA3072, specRSA4096, specSM2:
		return usage == usageEncrypt || usage == usageSign
	case specECP256, specECP384, specSECP256K1, specED25519:
		return usage == usageSign
	}
	return usage == defaultUsage(spec)
}

// generate makes new key material for a spec: raw bytes for symmetric
// and HMAC keys, PKCS #8 for the standard library's asymmetric ones, and
// the private scalar for SM2 and secp256k1.
func generate(spec string) ([]byte, error) {
	switch spec {
	case specAES256, specHMAC256, specHMACSM3:
		return random(32)
	case specSM4:
		return random(16)
	case specHMAC384:
		return random(48)
	case specHMAC512:
		return random(64)
	case specRSA2048, specRSA3072, specRSA4096:
		bits := map[string]int{specRSA2048: 2048, specRSA3072: 3072, specRSA4096: 4096}[spec]
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(k)
	case specECP256, specECP384:
		curve := elliptic.P256()
		if spec == specECP384 {
			curve = elliptic.P384()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(k)
	case specED25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(k)
	case specSM2:
		k, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return k.D.FillBytes(make([]byte, 32)), nil
	case specSECP256K1:
		k, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		return k.Serialize(), nil
	}
	return nil, fmt.Errorf("kms: unknown key spec %q", spec)
}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// digest is the hash that goes with a symmetric key's data keys: SM3 for
// SM4 keys, SHA-256 otherwise, as encrypt-datakey documents.
func digest(spec string) hash.Hash {
	if spec == specSM4 {
		return sm3.New()
	}
	return sha256.New()
}

// aead is the authenticated cipher of a symmetric key's material: AES-GCM
// or SM4-GCM.
func aead(spec string, k []byte) (cipher.AEAD, error) {
	var (
		block cipher.Block
		err   error
	)
	if spec == specSM4 {
		block, err = sm4.NewCipher(k)
	} else {
		block, err = aes.NewCipher(k)
	}
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// The envelope of a symmetric key's ciphertext. Like Huawei's, it names
// the key, so decrypt-data needs no key ID:
//
//	version (1) | account ID (16) | key ID (16) | material version (2)
//	| nonce (12) | data key sealed by the key's material (len + 16)
//	| nonce (12) | data sealed by the data key (len + 16)
//
// Each message has its own data key, of the key's own size. The data
// key's seal binds the header; the data's binds the caller's additional
// authenticated data.
const envelopeVersion = 1

// header is what an envelope names.
type header struct {
	account  [16]byte
	key      [16]byte
	material uint16
}

func (h header) bytes() []byte {
	b := make([]byte, 0, 35)
	b = append(b, envelopeVersion)
	b = append(b, h.account[:]...)
	b = append(b, h.key[:]...)
	return binary.BigEndian.AppendUint16(b, h.material)
}

const headerLen = 35

var errEnvelope = errors.New("kms: not a ciphertext of this emulator")

// seal encrypts plain under material (of spec), naming h.
func seal(spec string, material []byte, h header, plain, aad []byte) ([]byte, error) {
	dk, err := random(len(material))
	if err != nil {
		return nil, err
	}
	outer, err := aead(spec, material)
	if err != nil {
		return nil, err
	}
	inner, err := aead(spec, dk)
	if err != nil {
		return nil, err
	}
	hdr := h.bytes()
	n1, err := random(outer.NonceSize())
	if err != nil {
		return nil, err
	}
	n2, err := random(inner.NonceSize())
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, hdr...)
	out = append(out, n1...)
	out = outer.Seal(out, n1, dk, hdr)
	out = append(out, n2...)
	return inner.Seal(out, n2, plain, aad), nil
}

// parseHeader reads the header of an envelope.
func parseHeader(b []byte) (header, error) {
	if len(b) < headerLen || b[0] != envelopeVersion {
		return header{}, errEnvelope
	}
	var h header
	copy(h.account[:], b[1:17])
	copy(h.key[:], b[17:33])
	h.material = binary.BigEndian.Uint16(b[33:35])
	return h, nil
}

// open decrypts an envelope with the material it names (of spec).
func open(spec string, material, b, aad []byte) ([]byte, error) {
	outer, err := aead(spec, material)
	if err != nil {
		return nil, err
	}
	ns, tag, dkLen := outer.NonceSize(), outer.Overhead(), len(material)
	sealedDK := ns + dkLen + tag
	if len(b) < headerLen+sealedDK+ns+tag {
		return nil, errEnvelope
	}
	hdr, rest := b[:headerLen], b[headerLen:]
	dk, err := outer.Open(nil, rest[:ns], rest[ns:sealedDK], hdr)
	if err != nil {
		return nil, errEnvelope
	}
	inner, err := aead(spec, dk)
	if err != nil {
		return nil, err
	}
	rest = rest[sealedDK:]
	plain, err := inner.Open(nil, rest[:ns], rest[ns:], aad)
	if err != nil {
		return nil, errEnvelope
	}
	return plain, nil
}
