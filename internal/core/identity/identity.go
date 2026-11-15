// Package identity holds who exists in an emulator: its accounts
// (Huawei Cloud's "domains"), each account's project in each region, and
// the access keys WeiStack knows.
//
// The primary account is the emulator's own: the bootstrap
// administrator's keys act for it. Further accounts can be added, each
// with its root user's keys, to emulate delegation between accounts.
// Keys WeiStack does not know are accepted in accept mode as in v0.1.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// AccountName is the name of the emulator's primary account.
const AccountName = "weistack"

// Account is an account, the "domain" of Huawei Cloud's IAM.
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
	return a.DerivedProjectID(region)
}

// DerivedProjectID returns the project ID derived from the account and
// region, the same on every start: every project's but the primary
// account's in the default region.
func (a Account) DerivedProjectID(region string) string {
	sum := sha256.Sum256([]byte("weistack:project:" + a.ID + ":" + region))
	return hex.EncodeToString(sum[:16])
}

// RootUserID is the ID of the account's root user, its owner: the user
// the bootstrap administrator's keys belong to. It is derived from the
// account, so it never changes.
func (a Account) RootUserID() string {
	sum := sha256.Sum256([]byte("weistack:root-user:" + a.ID))
	return hex.EncodeToString(sum[:16])
}

// UserURN is the IAM 5.0 URN of a user: iam::<account-id>:user:<name>.
func (a Account) UserURN(userName string) string {
	return "iam::" + a.ID + ":user:" + userName
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
	// Disabled marks a key whose user is disabled. It still names its
	// user, but enforcement refuses it.
	Disabled bool

	// Temporary marks temporary credentials (a security token's).
	Temporary bool
	// AgencyID, AgencyName and SessionName name the agency an assumed
	// agency's credentials act as, in AccountID, and the session. UserID
	// and UserName are then empty.
	AgencyID, AgencyName, SessionName string
	// Session holds the policies temporary credentials were issued with,
	// if any. A pointer keeps Principal comparable.
	Session *Session
}

// Session is what narrows temporary credentials: an IAM 5.0 document and
// policy IDs (STS) apply to every service; a classic document (IAM's
// securitytokens) applies to OBS only, as Huawei documents.
type Session struct {
	Policy    string
	PolicyIDs []string
	OBSPolicy string
}

// TemporaryCredentials are an access key, its secret key and the
// security token that must accompany them, until ExpiresAt.
type TemporaryCredentials struct {
	AccessKey, SecretKey, SecurityToken string
	ExpiresAt                           time.Time
}

// Agency reports whether the principal is an assumed agency's session.
func (p Principal) Agency() bool { return p.AgencyID != "" }

// URN returns the principal's IAM 5.0 URN in account (whose name names
// its root user): a user's iam::<account-id>:user:<name>, or an assumed
// agency's sts::<account-id>:assumed-agency:<agency>/<session>. The
// administrator's key stands for the account's root user.
func (p Principal) URN(account Account) string {
	switch {
	case p.Agency():
		return "sts::" + account.ID + ":assumed-agency:" + p.AgencyName + "/" + p.SessionName
	case p.UserName != "" && !p.Admin:
		return account.UserURN(p.UserName)
	}
	return account.UserURN(account.Name)
}

// The lockout Huawei documents for AK/SK authentication: more than five
// consecutive failures lock the access key for five minutes.
const (
	MaxFailures = 5
	LockFor     = 5 * time.Minute
)

type entry struct {
	principal Principal
	// secret is the secret key, kept in memory to check signatures.
	secret string
	// root marks an added account's root key: like the administrator's,
	// it is never replaced or forgotten while its account exists.
	root bool
}

// protected reports whether e is the administrator's key or an account's
// root key, which only the account's removal forgets.
func (e entry) protected() bool { return e.principal.Admin || e.root }

type lockout struct {
	failures int
	until    time.Time
}

// Directory maps access keys to principals and their secret keys,
// remembers when each key was last used, and counts signature failures.
// It is safe for concurrent use. Secrets are never logged.
type Directory struct {
	account Account
	now     func() time.Time

	// accounts are those added besides the primary one, by ID.
	accounts map[string]Account

	mu       sync.RWMutex
	keys     map[string]entry
	lastUsed map[string]time.Time
	locks    map[string]*lockout
}

// NewDirectory returns a directory for account in which admin's key is
// the administrator's.
func NewDirectory(account Account, admin Credentials) *Directory {
	d := &Directory{
		account: account, now: time.Now, accounts: map[string]Account{},
		keys: map[string]entry{}, lastUsed: map[string]time.Time{}, locks: map[string]*lockout{},
	}
	d.keys[admin.AccessKey] = entry{
		principal: Principal{AccountID: account.ID, UserName: "admin", Admin: true},
		secret:    admin.SecretKey,
	}
	return d
}

// Account returns the emulator's primary account.
func (d *Directory) Account() Account { return d.account }

// AddAccount adds an account whose root user holds root's keys. Account
// IDs, names and keys must all be unused.
func (d *Directory) AddAccount(a Account, root Credentials) error {
	if !a.Valid() {
		return fmt.Errorf("identity: account %q (%s) is not valid", a.Name, a.ID)
	}
	if !root.Valid() {
		return errors.New("identity: the root user's keys are not valid")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, other := range d.accountsLocked() {
		switch {
		case other.ID == a.ID:
			return fmt.Errorf("%w: an account has the ID %s", ErrAccountExists, a.ID)
		case strings.EqualFold(other.Name, a.Name):
			return fmt.Errorf("%w: an account is named %s", ErrAccountExists, a.Name)
		}
	}
	if _, ok := d.keys[root.AccessKey]; ok {
		return fmt.Errorf("%w: %s", ErrKeyTaken, root.AccessKey)
	}
	d.accounts[a.ID] = a
	d.keys[root.AccessKey] = entry{
		principal: Principal{AccountID: a.ID, UserID: a.RootUserID(), UserName: a.Name},
		secret:    root.SecretKey, root: true,
	}
	return nil
}

// Errors of AddAccount.
var (
	ErrAccountExists = errors.New("identity: the account exists")
	ErrKeyTaken      = errors.New("identity: the access key is taken")
)

// Accounts returns every account: the primary one first, then the added
// ones by name.
func (d *Directory) Accounts() []Account {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.accountsLocked()
}

func (d *Directory) accountsLocked() []Account {
	out := make([]Account, 0, 1+len(d.accounts))
	for _, a := range d.accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return append([]Account{d.account}, out...)
}

// AccountByID returns the account with that ID.
func (d *Directory) AccountByID(id string) (Account, bool) {
	if id == d.account.ID {
		return d.account, true
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	a, ok := d.accounts[id]
	return a, ok
}

// AccountByName returns the account with that name, ignoring case as
// Huawei Cloud's account names do.
func (d *Directory) AccountByName(name string) (Account, bool) {
	for _, a := range d.Accounts() {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Account{}, false
}

// Primary reports whether a is the emulator's primary account.
func (d *Directory) Primary(a Account) bool { return a.ID == d.account.ID }

// Lookup returns the principal an access key belongs to, if WeiStack
// knows the key.
func (d *Directory) Lookup(accessKey string) (Principal, bool) {
	if d == nil || accessKey == "" {
		return Principal{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	e, ok := d.keys[accessKey]
	return e.principal, ok
}

// Secret returns the secret key of a known access key.
func (d *Directory) Secret(accessKey string) (string, bool) {
	if d == nil || accessKey == "" {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	e, ok := d.keys[accessKey]
	return e.secret, ok && e.secret != ""
}

// Register makes accessKey known as p, with its secret key, replacing
// any earlier entry. It refuses to take over the administrator's key or
// an account's root key.
func (d *Directory) Register(accessKey string, p Principal, secret string) error {
	if !ValidKey(accessKey) {
		return fmt.Errorf("identity: %q is not a valid access key", accessKey)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.keys[accessKey]; ok && old.protected() {
		return fmt.Errorf("%w: %s is the administrator's or an account's root key", ErrKeyTaken, accessKey)
	}
	d.keys[accessKey] = entry{principal: p, secret: secret}
	return nil
}

// Forget removes a key, when it was last used and its failures, except
// the administrator's and the accounts' root keys.
func (d *Directory) Forget(accessKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.keys[accessKey]; ok && !e.protected() {
		delete(d.keys, accessKey)
		delete(d.lastUsed, accessKey)
		delete(d.locks, accessKey)
	}
}

// Clear forgets every added account and every key but the
// administrator's, as at start.
func (d *Directory) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.accounts)
	for k, e := range d.keys {
		if !e.principal.Admin {
			delete(d.keys, k)
			delete(d.lastUsed, k)
		}
	}
	clear(d.locks)
}

// KeyUsed records that a request was made with accessKey, if the key is
// known. Times are kept in memory only.
func (d *Directory) KeyUsed(accessKey string) {
	if d == nil {
		return
	}
	now := d.now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.keys[accessKey]; ok {
		d.lastUsed[accessKey] = now
	}
}

// LastUsed returns when accessKey was last used since it became known, or
// false if it has not been.
func (d *Directory) LastUsed(accessKey string) (time.Time, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	t, ok := d.lastUsed[accessKey]
	return t, ok
}

// Locked reports whether accessKey is locked out after too many failed
// signatures. The administrator's key is never locked, so that a typo
// cannot lock out the emulator's operator.
func (d *Directory) Locked(accessKey string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	l, ok := d.locks[accessKey]
	return ok && d.now().Before(l.until)
}

// SignatureFailed counts a failed signature for accessKey. The failure
// after MaxFailures in a row locks the key for LockFor.
func (d *Directory) SignatureFailed(accessKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.keys[accessKey]
	if !ok || e.principal.Admin {
		return // the operator's key is never locked
	}
	l := d.locks[accessKey]
	if l == nil {
		l = &lockout{}
		d.locks[accessKey] = l
	}
	if now := d.now(); !l.until.IsZero() && !now.Before(l.until) {
		*l = lockout{} // the last lock has passed: count afresh
	}
	l.failures++
	if l.failures > MaxFailures {
		l.until = d.now().Add(LockFor)
	}
}

// SignatureSucceeded clears accessKey's failures.
func (d *Directory) SignatureSucceeded(accessKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.locks, accessKey)
}
