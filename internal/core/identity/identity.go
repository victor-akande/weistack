// Package identity holds who exists in an emulator: its one account
// (Huawei Cloud's "domain"), the account's project in each region, and
// the access keys WeiStack knows.
//
// In this release the only known key is the bootstrap administrator's.
// Every other key is accepted as in v0.1 and stands for an account of its
// own. Later releases register IAM users' keys here, and enforcement
// checks signatures and policies against them.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"sync"
)

// AccountName is the name of the emulator's account.
const AccountName = "weistack"

// Account is the emulator's account, the "domain" of Huawei Cloud's IAM.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var hex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Valid reports whether the account is well formed.
func (a Account) Valid() bool { return hex32RE.MatchString(a.ID) && a.Name != "" }

// ProjectID returns the account's project in region. The default region
// keeps the emulator's configured project ID, as in v0.1; every other
// region gets an ID derived from the account, the same on every start.
func (a Account) ProjectID(region, defaultRegion, defaultProjectID string) string {
	if region == defaultRegion {
		return defaultProjectID
	}
	sum := sha256.Sum256([]byte("weistack:project:" + a.ID + ":" + region))
	return hex.EncodeToString(sum[:16])
}

// Credentials are a permanent access key pair.
type Credentials struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

// Lengths of generated keys: Huawei Cloud's access keys are 20
// characters, its secret keys 40.
const (
	AccessKeyLen = 20
	SecretKeyLen = 40
)

var keyRE = regexp.MustCompile(`^[A-Za-z0-9]{8,128}$`)

// ValidKey reports whether s can be an access or secret key: 8 to 128
// letters and digits. Signature formats split on other characters.
func ValidKey(s string) bool { return keyRE.MatchString(s) }

// Valid reports whether both keys are well formed.
func (c Credentials) Valid() bool { return ValidKey(c.AccessKey) && ValidKey(c.SecretKey) }

// NewCredentials generates a key pair shaped like Huawei Cloud's: an
// access key of 20 upper-case letters and digits, a secret key of 40
// letters and digits.
func NewCredentials() (Credentials, error) {
	ak, err := randomString(AccessKeyLen, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err != nil {
		return Credentials{}, err
	}
	sk, err := randomString(SecretKeyLen, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessKey: ak, SecretKey: sk}, nil
}

// NewAccount generates an account.
func NewAccount() (Account, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Account{}, err
	}
	return Account{ID: hex.EncodeToString(b), Name: AccountName}, nil
}

func randomString(n int, alphabet string) (string, error) {
	out := make([]byte, n)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range out {
		k, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[k.Int64()]
	}
	return string(out), nil
}

// Principal is who an access key belongs to.
type Principal struct {
	// AccountID is the account the key acts for.
	AccountID string
	// UserID and UserName name the user, when the key is a user's.
	UserID   string
	UserName string
	// Admin marks the bootstrap administrator.
	Admin bool
}

// Directory maps access keys to principals. It is safe for concurrent
// use.
type Directory struct {
	account Account

	mu   sync.RWMutex
	keys map[string]Principal
}

// NewDirectory returns a directory for account in which admin's key is
// the administrator's.
func NewDirectory(account Account, admin Credentials) *Directory {
	d := &Directory{account: account, keys: map[string]Principal{}}
	d.keys[admin.AccessKey] = Principal{AccountID: account.ID, UserName: "admin", Admin: true}
	return d
}

// Account returns the emulator's account.
func (d *Directory) Account() Account { return d.account }

// Lookup returns the principal an access key belongs to, if WeiStack
// knows the key.
func (d *Directory) Lookup(accessKey string) (Principal, bool) {
	if d == nil || accessKey == "" {
		return Principal{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.keys[accessKey]
	return p, ok
}

// Register makes accessKey known as p, replacing any earlier entry. It
// refuses to take over the administrator's key.
func (d *Directory) Register(accessKey string, p Principal) error {
	if !ValidKey(accessKey) {
		return fmt.Errorf("identity: %q is not a valid access key", accessKey)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.keys[accessKey]; ok && old.Admin {
		return fmt.Errorf("identity: %s is the administrator's key", accessKey)
	}
	d.keys[accessKey] = p
	return nil
}

// Forget removes a key, except the administrator's.
func (d *Directory) Forget(accessKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.keys[accessKey]; ok && !p.Admin {
		delete(d.keys, accessKey)
	}
}
