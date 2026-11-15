package identity

import (
	"errors"
	"regexp"
	"testing"
	"time"
)

func TestNewCredentialsLookLikeHuaweiKeys(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for range 50 {
		c, err := NewCredentials()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[A-Z0-9]{20}$`).MatchString(c.AccessKey) || !regexp.MustCompile(`^[A-Za-z0-9]{40}$`).MatchString(c.SecretKey) || !c.Valid() {
			t.Fatalf("credentials %q / %q", c.AccessKey, c.SecretKey)
		}
		if seen[c.AccessKey] {
			t.Fatal("a generated access key repeated")
		}
		seen[c.AccessKey] = true
	}
}

func TestValidKey(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]bool{
		"AKFIXTURE": true, "abcdefgh": true, "short": false, "with space": false, "has:colon": false,
		"": false, string(make([]byte, 129)): false,
	} {
		if got := ValidKey(key); got != want {
			t.Errorf("ValidKey(%q) = %v", key, got)
		}
	}
}

func TestProjectIDs(t *testing.T) {
	t.Parallel()
	a := Account{ID: "0123456789abcdef0123456789abcdef", Name: AccountName}
	const def = "fedcba9876543210fedcba9876543210"
	if got := a.ProjectID("ap-southeast-1", "ap-southeast-1", def); got != def {
		t.Fatalf("the default region's project = %s, want the configured %s", got, def)
	}
	other := a.ProjectID("cn-north-4", "ap-southeast-1", def)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(other) || other == def {
		t.Fatalf("another region's project = %q", other)
	}
	if again := a.ProjectID("cn-north-4", "ap-southeast-1", def); again != other {
		t.Fatal("a region's project ID changed")
	}
	if a.ProjectID("eu-west-101", "ap-southeast-1", def) == other {
		t.Fatal("two regions share a project ID")
	}
	b := Account{ID: "ffffffffffffffffffffffffffffffff", Name: AccountName}
	if b.ProjectID("cn-north-4", "ap-southeast-1", def) == other {
		t.Fatal("two accounts share a project ID")
	}
}

func TestNewAccount(t *testing.T) {
	t.Parallel()
	a, err := NewAccount()
	if err != nil || !a.Valid() || a.Name != "weistack" {
		t.Fatalf("NewAccount() = %+v, %v", a, err)
	}
	if (Account{ID: "nope", Name: "x"}).Valid() || (Account{ID: a.ID}).Valid() {
		t.Fatal("an invalid account passed")
	}
}

func TestDirectory(t *testing.T) {
	t.Parallel()
	acct := Account{ID: "0123456789abcdef0123456789abcdef", Name: AccountName}
	admin := Credentials{AccessKey: "ADMINKEY00000000000A", SecretKey: "secret"}
	d := NewDirectory(acct, admin)

	if p, ok := d.Lookup(admin.AccessKey); !ok || !p.Admin || p.AccountID != acct.ID {
		t.Fatalf("admin lookup = %+v, %v", p, ok)
	}
	if _, ok := d.Lookup("SOMEONEELSE"); ok {
		t.Fatal("an unknown key resolved")
	}
	if _, ok := d.Lookup(""); ok {
		t.Fatal("an empty key resolved")
	}
	var nilDir *Directory
	if _, ok := nilDir.Lookup("x"); ok {
		t.Fatal("a nil directory resolved a key")
	}

	user := Principal{AccountID: acct.ID, UserID: "u1", UserName: "alice"}
	if err := d.Register("USERKEY000000000000A", user, "secret"); err != nil {
		t.Fatal(err)
	}
	if p, ok := d.Lookup("USERKEY000000000000A"); !ok || p.UserName != "alice" || p.Admin {
		t.Fatalf("user lookup = %+v, %v", p, ok)
	}
	if err := d.Register(admin.AccessKey, user, ""); err == nil {
		t.Fatal("a user took over the administrator's key")
	}
	if err := d.Register("bad key", user, ""); err == nil {
		t.Fatal("an invalid key was registered")
	}
	d.Forget("USERKEY000000000000A")
	d.Forget(admin.AccessKey)
	if _, ok := d.Lookup("USERKEY000000000000A"); ok {
		t.Fatal("a forgotten key still resolves")
	}
	if _, ok := d.Lookup(admin.AccessKey); !ok {
		t.Fatal("the administrator's key was forgotten")
	}
	if d.Account() != acct {
		t.Fatal("Account() changed")
	}
}

func TestDirectoryLastUsedAndClear(t *testing.T) {
	t.Parallel()
	acct := Account{ID: "0123456789abcdef0123456789abcdef", Name: AccountName}
	admin := Credentials{AccessKey: "ADMINKEY00000000000A", SecretKey: "secret"}
	d := NewDirectory(acct, admin)
	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	const key = "USERKEY000000000000A"

	d.KeyUsed(key) // unknown: not recorded
	if _, ok := d.LastUsed(key); ok {
		t.Fatal("an unknown key has a last use")
	}
	if err := d.Register(key, Principal{AccountID: acct.ID, UserID: "u1", UserName: "alice"}, "secret"); err != nil {
		t.Fatal(err)
	}
	d.KeyUsed(key)
	if got, ok := d.LastUsed(key); !ok || !got.Equal(at) {
		t.Fatalf("LastUsed = %v, %v", got, ok)
	}
	var nilDir *Directory
	nilDir.KeyUsed(key) // no panic

	d.Clear()
	if _, ok := d.Lookup(key); ok {
		t.Fatal("Clear kept a user's key")
	}
	if _, ok := d.LastUsed(key); ok {
		t.Fatal("Clear kept a last use")
	}
	if _, ok := d.Lookup(admin.AccessKey); !ok {
		t.Fatal("Clear forgot the administrator's key")
	}
}

func TestDirectorySecretsAndLockout(t *testing.T) {
	t.Parallel()
	acct := Account{ID: "0123456789abcdef0123456789abcdef", Name: AccountName}
	admin := Credentials{AccessKey: "ADMINKEY00000000000A", SecretKey: "admin-secret"}
	d := NewDirectory(acct, admin)
	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	const key = "USERKEY000000000000A"

	if s, ok := d.Secret(admin.AccessKey); !ok || s != "admin-secret" {
		t.Fatalf("admin secret = %q, %v", s, ok)
	}
	if _, ok := d.Secret(key); ok {
		t.Fatal("an unknown key has a secret")
	}
	if err := d.Register(key, Principal{AccountID: acct.ID, UserID: "u1", UserName: "alice", Disabled: true}, "user-secret"); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.Lookup(key); !p.Disabled {
		t.Fatal("Disabled was lost")
	}
	if s, ok := d.Secret(key); !ok || s != "user-secret" {
		t.Fatalf("user secret = %q, %v", s, ok)
	}

	// Five failures in a row are allowed; the sixth locks the key for
	// five minutes.
	for range MaxFailures {
		d.SignatureFailed(key)
	}
	if d.Locked(key) {
		t.Fatal("locked after five failures")
	}
	d.SignatureFailed(key)
	if !d.Locked(key) {
		t.Fatal("not locked after six failures")
	}
	at = at.Add(LockFor)
	if d.Locked(key) {
		t.Fatal("still locked after five minutes")
	}
	// After the lock, counting starts again; a success clears it.
	d.SignatureFailed(key)
	if d.Locked(key) {
		t.Fatal("locked again by one failure")
	}
	d.SignatureSucceeded(key)
	for range MaxFailures {
		d.SignatureFailed(key)
	}
	if d.Locked(key) {
		t.Fatal("a success did not reset the count")
	}

	// The administrator's key is never locked.
	for range 3 * MaxFailures {
		d.SignatureFailed(admin.AccessKey)
	}
	if d.Locked(admin.AccessKey) {
		t.Fatal("the administrator's key was locked")
	}
}

func TestDirectoryAccounts(t *testing.T) {
	t.Parallel()
	primary, admin := mustAccount(t, AccountName), mustCreds(t)
	d := NewDirectory(primary, admin)
	partner, root := mustAccount(t, "partner"), mustCreds(t)
	if err := d.AddAccount(partner, root); err != nil {
		t.Fatal(err)
	}

	p, ok := d.Lookup(root.AccessKey)
	if !ok || p.AccountID != partner.ID || p.UserID != partner.RootUserID() || p.UserName != "partner" || p.Admin {
		t.Fatalf("the root key's principal = %+v, %v", p, ok)
	}
	if got := d.Accounts(); len(got) != 2 || got[0] != primary || got[1] != partner {
		t.Errorf("Accounts() = %v", got)
	}
	if a, ok := d.AccountByName("PARTNER"); !ok || a != partner {
		t.Errorf("AccountByName = %v, %v", a, ok)
	}
	if a, ok := d.AccountByID(primary.ID); !ok || !d.Primary(a) || d.Primary(partner) {
		t.Errorf("AccountByID(primary) = %v, %v", a, ok)
	}

	// Names, IDs and keys are unique; root keys are protected.
	if err := d.AddAccount(mustAccount(t, "Partner"), mustCreds(t)); !errors.Is(err, ErrAccountExists) {
		t.Errorf("a second account named partner: %v", err)
	}
	if err := d.AddAccount(Account{ID: partner.ID, Name: "other"}, mustCreds(t)); !errors.Is(err, ErrAccountExists) {
		t.Errorf("a second account with partner's ID: %v", err)
	}
	if err := d.AddAccount(mustAccount(t, "other"), admin); !errors.Is(err, ErrKeyTaken) {
		t.Errorf("an account with the administrator's key: %v", err)
	}
	if err := d.Register(root.AccessKey, Principal{AccountID: primary.ID, UserID: "u"}, "s"); !errors.Is(err, ErrKeyTaken) {
		t.Errorf("registering over a root key: %v", err)
	}
	d.Forget(root.AccessKey)
	if _, ok := d.Lookup(root.AccessKey); !ok {
		t.Error("Forget removed a root key")
	}

	// Clear returns to the start: the primary account and the administrator.
	d.Clear()
	if _, ok := d.Lookup(root.AccessKey); ok {
		t.Error("Clear kept an added account's root key")
	}
	if got := d.Accounts(); len(got) != 1 || got[0] != primary {
		t.Errorf("after Clear, Accounts() = %v", got)
	}
}

func mustAccount(t *testing.T, name string) Account {
	t.Helper()
	a, err := NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	a.Name = name
	return a
}

func mustCreds(t *testing.T) Credentials {
	t.Helper()
	c, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	return c
}
