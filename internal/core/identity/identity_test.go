package identity

import (
	"regexp"
	"testing"
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
	if err := d.Register("USERKEY000000000000A", user); err != nil {
		t.Fatal(err)
	}
	if p, ok := d.Lookup("USERKEY000000000000A"); !ok || p.UserName != "alice" || p.Admin {
		t.Fatalf("user lookup = %+v, %v", p, ok)
	}
	if err := d.Register(admin.AccessKey, user); err == nil {
		t.Fatal("a user took over the administrator's key")
	}
	if err := d.Register("bad key", user); err == nil {
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
