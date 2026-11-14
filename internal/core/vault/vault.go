// Package vault seals secrets that WeiStack must keep but must not store
// in clear text, such as the secret keys of IAM users' access keys:
// signature checks need them back, so they cannot be hashed like
// passwords.
//
// Sealing is AES-256-GCM. Each sealed value is bound to a label, such as
// its access key, so a sealed value copied to another record does not
// open there.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeyLen is the length of a vault key in bytes.
const KeyLen = 32

// Vault seals and opens secrets with one key. It is safe for concurrent
// use.
type Vault struct {
	aead cipher.AEAD
}

// New returns a vault that uses key, which must be KeyLen bytes.
func New(key []byte) (*Vault, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("vault: the key has %d bytes, want %d", len(key), KeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// NewKey generates a random vault key.
func NewKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts secret, bound to label. The result holds the nonce
// followed by the ciphertext.
func (v *Vault) Seal(secret, label string) ([]byte, error) {
	nonce := make([]byte, v.aead.NonceSize(), v.aead.NonceSize()+len(secret)+v.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return v.aead.Seal(nonce, nonce, []byte(secret), []byte(label)), nil
}

// ErrOpen is returned for a value that was not sealed by this vault's key
// with this label, or was altered.
var ErrOpen = errors.New("vault: cannot open the sealed value")

// Open decrypts a value Seal returned for label.
func (v *Vault) Open(sealed []byte, label string) (string, error) {
	n := v.aead.NonceSize()
	if len(sealed) < n {
		return "", ErrOpen
	}
	plain, err := v.aead.Open(nil, sealed[:n], sealed[n:], []byte(label))
	if err != nil {
		return "", ErrOpen
	}
	return string(plain), nil
}
