package kms

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	msg := []byte("release v0.2.0")
	sha := sha256.Sum256(msg)
	sha5 := sha512.Sum512(msg)
	sm := sm3.Sum(msg)
	for _, c := range []struct {
		spec, alg, typ string
		message        []byte
	}{
		{"RSA_2048", "RSASSA_PSS_SHA_256", "", sha[:]},
		{"RSA_2048", "RSASSA_PKCS1_V1_5_SHA_512", "RAW", msg},
		{"EC_P256", "ECDSA_SHA_256", "DIGEST", sha[:]},
		{"EC_P384", "ECDSA_SHA_512", "", sha5[:]},
		{"SECP256K1", "ECDSA_SHA_256", "RAW", msg},
		{"SM2", "SM2DSA_SM3", "", sm[:]},
		{"ED25519", "ED25519_SHA_512", "RAW", msg},
		{"ED25519", "ED25519_PH_SHA_512", "", sha5[:]},
	} {
		id := e.newKey(t, `{"key_alias":"sign-`+strings.ToLower(c.spec+"-"+c.alg)+`","key_spec":"`+c.spec+`"}`)
		body := `{"key_id":"` + id + `","signing_algorithm":"` + c.alg + `","message_type":"` + c.typ + `","message":"` + b64(c.message) + `"`
		if c.typ == "" {
			body = `{"key_id":"` + id + `","signing_algorithm":"` + c.alg + `","message":"` + b64(c.message) + `"`
		}
		sig := e.ok(t, "sign", body+`}`)["signature"].(string)
		if got := e.ok(t, "verify", body+`,"signature":"`+sig+`"}`)["signature_valid"]; got != "true" {
			t.Errorf("%s %s: verify = %v", c.spec, c.alg, got)
		}
		other := sha256.Sum256([]byte("something else"))
		wrong := `{"key_id":"` + id + `","signing_algorithm":"` + c.alg + `","message":"` + b64(other[:]) + `","signature":"` + sig + `"`
		if c.typ == "RAW" {
			wrong += `,"message_type":"RAW"`
		}
		if c.alg == "ECDSA_SHA_512" || c.alg == "ED25519_PH_SHA_512" {
			o := sha512.Sum512([]byte("something else"))
			wrong = `{"key_id":"` + id + `","signing_algorithm":"` + c.alg + `","message":"` + b64(o[:]) + `","signature":"` + sig + `"`
		}
		if got := e.ok(t, "verify", wrong+`}`)["signature_valid"]; got != "false" {
			t.Errorf("%s %s: another message verifies: %v", c.spec, c.alg, got)
		}
		// The public key is PEM, and the standard library reads the
		// standard curves' and RSA's.
		pk := e.ok(t, "get-publickey", ref(id))["public_key"].(string)
		block, _ := pem.Decode([]byte(pk))
		if block == nil || block.Type != "PUBLIC KEY" || !strings.Contains(pk, "\r\n") {
			t.Errorf("%s: public key %q", c.spec, pk)
			continue
		}
		if c.spec != "SM2" && c.spec != "SECP256K1" {
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				t.Errorf("%s: public key: %v", c.spec, err)
			}
		}
	}

	ec := e.newKey(t, `{"key_alias":"errs","key_spec":"EC_P256"}`)
	sm2 := e.newKey(t, `{"key_alias":"errs-sm2","key_spec":"SM2"}`)
	aes := e.newKey(t, `{"key_alias":"errs-aes"}`)
	for _, c := range []struct{ body, code string }{
		{`{"key_id":"` + ec + `","signing_algorithm":"RSASSA_PSS_SHA_256","message":"` + b64(sha[:]) + `"}`, "KMS.0332"},
		{`{"key_id":"` + ec + `","signing_algorithm":"ECDSA_SHA_384","message":"` + b64(sha[:]) + `"}`, "KMS.0329"},
		{`{"key_id":"` + sm2 + `","signing_algorithm":"SM2DSA_SM3","message_type":"RAW","message":"` + b64(msg) + `"}`, "KMS.0333"},
		{`{"key_id":"` + aes + `","signing_algorithm":"ECDSA_SHA_256","message":"` + b64(sha[:]) + `"}`, "KMS.1115"},
	} {
		e.wantErr(t, 400, c.code, "sign", c.body)
	}
	e.wantErr(t, 400, "KMS.0331", "get-publickey", ref(aes))
}

func TestAsymmetricEncryption(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for spec, alg := range map[string]string{"RSA_2048": "RSAES_OAEP_SHA_256", "SM2": "SM2_ENCRYPT"} {
		id := e.newKey(t, `{"key_alias":"pke-`+strings.ToLower(spec)+`","key_spec":"`+spec+`","key_usage":"ENCRYPT_DECRYPT"}`)
		ct := e.ok(t, "encrypt-data", `{"key_id":"`+id+`","plain_text":"secret","encryption_algorithm":"`+alg+`"}`)["cipher_text"].(string)
		out := e.ok(t, "decrypt-data", `{"key_id":"`+id+`","cipher_text":"`+ct+`","encryption_algorithm":"`+alg+`"}`)
		if out["plain_text"] != "secret" {
			t.Errorf("%s: decrypt = %v", spec, out)
		}
		code := "KMS.2106"
		if spec == "SM2" {
			code = "KMS.2107"
		}
		e.wantErr(t, 400, code, "encrypt-data", `{"key_id":"`+id+`","plain_text":"x"}`)
		e.wantErr(t, 400, "KMS.0334", "sign", `{"key_id":"`+id+`","signing_algorithm":"SM2DSA_SM3","message":"`+b64(make([]byte, 32))+`"}`)
	}
	rsa := e.newKey(t, `{"key_alias":"pke-long","key_spec":"RSA_2048","key_usage":"ENCRYPT_DECRYPT"}`)
	e.wantErr(t, 400, "KMS.2108", "encrypt-data", `{"key_id":"`+rsa+`","plain_text":"`+strings.Repeat("x", 200)+`","encryption_algorithm":"RSAES_OAEP_SHA_256"}`)
}

func TestMACs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for spec, alg := range map[string]string{"HMAC_256": "HMAC_SHA_256", "HMAC_384": "HMAC_SHA_384", "HMAC_512": "HMAC_SHA_512", "HMAC_SM3": "HMAC_SM3"} {
		id := e.newKey(t, `{"key_alias":"mac-`+strings.ToLower(spec)+`","key_spec":"`+spec+`"}`)
		body := `{"key_id":"` + id + `","mac_algorithm":"` + alg + `","message":"` + b64([]byte("fdsa")) + `"`
		mac := e.ok(t, "generate-mac", body+`}`)["mac"].(string)
		if strings.ToLower(mac) != mac {
			t.Errorf("%s: mac %q", spec, mac)
		}
		if got := e.ok(t, "verify-mac", body+`,"mac":"`+mac+`"}`)["mac_valid"]; got != true {
			t.Errorf("%s: verify = %v", spec, got)
		}
		if got := e.ok(t, "verify-mac", body+`,"mac":"00"}`)["mac_valid"]; got != false {
			t.Errorf("%s: a wrong mac verifies", spec)
		}
		e.wantErr(t, 400, "KMS.0308", "generate-mac", `{"key_id":"`+id+`","mac_algorithm":"HMAC_SHA_1","message":"eA=="}`)
	}
	aes := e.newKey(t, `{"key_alias":"mac-aes"}`)
	e.wantErr(t, 400, "KMS.0308", "generate-mac", `{"key_id":"`+aes+`","mac_algorithm":"HMAC_SHA_256","message":"eA=="}`)
}
