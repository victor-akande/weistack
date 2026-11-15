package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Accounts besides the primary one, added through the emulator's admin
// API to emulate delegation between accounts. Each is an empty account
// like the primary one at first start: a root user, which holds the keys
// it was added with, the admin group, and a project in every region.
//
// They are kept in the primary account's scope, with the root user's
// secret key sealed, so -persist keeps them; a reset removes them, as it
// returns the emulator to its start.

const kindAccount = "iam.account"

// accountRecord is an added account and its root user's keys.
type accountRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AccessKey string    `json:"access_key"`
	Secret    []byte    `json:"secret"` // sealed, bound to the access key
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) accountRecords() store.Collection[accountRecord] {
	return store.Of[accountRecord](s.store, global(kindAccount))
}

// Account errors, in the emulator's admin API's own codes: they are not
// Huawei Cloud's.
var (
	errAccountName   = apierr.New(400, "WeiStack.0400", "the account name must be 1 to 32 letters, digits, spaces, hyphens, underscores or periods, starting with a letter")
	errAccountKeys   = apierr.New(400, "WeiStack.0400", "access_key and secret_key must be given together, each of 8 to 128 letters and digits")
	errAccountExists = apierr.New(409, "WeiStack.0409", "an account with that name, or that access key, exists")
)

// NewAccount adds an account named name whose root user holds root's
// keys, or generated ones if root is nil, and returns them.
func (s *Service) NewAccount(ctx context.Context, name string, root *identity.Credentials) (identity.Account, identity.Credentials, error) {
	if !validUsername(name) {
		return identity.Account{}, identity.Credentials{}, errAccountName
	}
	var creds identity.Credentials
	switch {
	case root == nil:
		c, err := identity.NewCredentials()
		if err != nil {
			return identity.Account{}, identity.Credentials{}, err
		}
		creds = c
	case !root.Valid():
		return identity.Account{}, identity.Credentials{}, errAccountKeys
	default:
		creds = *root
	}
	acct, err := identity.NewAccount()
	if err != nil {
		return identity.Account{}, identity.Credentials{}, err
	}
	acct.Name = name

	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.perms.changed()
	if err := s.dir.AddAccount(acct, creds); errors.Is(err, identity.ErrAccountExists) || errors.Is(err, identity.ErrKeyTaken) {
		return identity.Account{}, identity.Credentials{}, errAccountExists
	} else if err != nil {
		return identity.Account{}, identity.Credentials{}, err
	}
	sealed, err := s.vault.Seal(creds.SecretKey, creds.AccessKey)
	if err != nil {
		return identity.Account{}, identity.Credentials{}, err
	}
	rec := accountRecord{ID: acct.ID, Name: acct.Name, AccessKey: creds.AccessKey, Secret: sealed, CreatedAt: s.now().UTC()}
	if err := s.accountRecords().Create(ctx, rec.ID, rec); err != nil {
		return identity.Account{}, identity.Credentials{}, err
	}
	if err := s.prepare(withAccount(ctx, acct)); err != nil {
		return identity.Account{}, identity.Credentials{}, err
	}
	return acct, creds, nil
}

// Accounts returns every account, the primary one first.
func (s *Service) Accounts() []identity.Account { return s.dir.Accounts() }

// ProjectIDOf returns a's project in region.
func (s *Service) ProjectIDOf(a identity.Account, region string) string {
	return s.projectID(a, region)
}

// resumeAccounts adds the stored accounts to the directory and prepares
// them.
func (s *Service) resumeAccounts(ctx context.Context) error {
	recs, err := s.accountRecords().List(ctx, nil)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		secret, err := s.vault.Open(rec.Secret, rec.AccessKey)
		if err != nil {
			return fmt.Errorf("iam: opening the root key of account %s: %w", rec.Name, err)
		}
		acct := identity.Account{ID: rec.ID, Name: rec.Name}
		creds := identity.Credentials{AccessKey: rec.AccessKey, SecretKey: secret}
		if err := s.dir.AddAccount(acct, creds); err != nil {
			return fmt.Errorf("iam: account %s: %w", rec.Name, err)
		}
		if err := s.prepare(withAccount(ctx, acct)); err != nil {
			return err
		}
	}
	return nil
}

// prepare records ctx's account's default-region project, root user and
// admin group, and registers its users' access keys.
func (s *Service) prepare(ctx context.Context) error {
	if err := s.ensureProject(ctx, s.defaultRegion); err != nil {
		return err
	}
	if err := s.ensureRoot(ctx); err != nil {
		return err
	}
	if err := s.ensureAdminGroup(ctx); err != nil {
		return err
	}
	return s.registerAllKeys(ctx)
}
