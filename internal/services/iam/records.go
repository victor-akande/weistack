package iam

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/store"
)

// The records both API generations share. A user created with classic
// IAM is the same user through /v5, and the other way round.

const (
	kindUser  = "iam.user"
	kindGroup = "iam.group"
)

// maxUsers is classic IAM's default quota of IAM users, the root user not
// included (productdesc-iam/iam_01_0305).
const maxUsers = 50

// user is an IAM user. The root user is the account itself; it holds the
// bootstrap administrator's keys and cannot be renamed, disabled or
// deleted.
type user struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Root        bool   `json:"root,omitempty"`
	// AccessMode is "default" (console and API), "console" or
	// "programmatic".
	AccessMode string `json:"access_mode"`
	Email      string `json:"email,omitempty"`
	AreaCode   string `json:"areacode,omitempty"`
	Phone      string `json:"phone,omitempty"`
	// PwdStatus true means the password must be changed at next login.
	PwdStatus bool `json:"pwd_status,omitempty"`
	// Password is a salted hash, never the password.
	Password          *passwordHash `json:"password,omitempty"`
	PasswordChangedAt time.Time     `json:"password_changed_at,omitzero"`
	LoginProtect      loginProtect  `json:"login_protect"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	LastLoginAt       time.Time     `json:"last_login_at,omitzero"`
}

type loginProtect struct {
	Enabled bool   `json:"enabled"`
	Method  string `json:"verification_method,omitempty"`
}

// group is a user group. Members are user IDs, in the order they joined.
type group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Members     []string  `json:"members,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (g group) has(userID string) bool { return slices.Contains(g.Members, userID) }

func global(kind string) store.Scope {
	return store.Scope{Region: store.Global, ProjectID: store.Global, Kind: kind}
}

func (s *Service) users() store.Collection[user] { return store.Of[user](s.store, global(kindUser)) }

func (s *Service) groups() store.Collection[group] {
	return store.Of[group](s.store, global(kindGroup))
}

// ensureRoot records the root user, if it is not yet known.
func (s *Service) ensureRoot(ctx context.Context) error {
	acct := s.account()
	now := s.now().UTC()
	root := user{
		ID: acct.RootUserID(), Name: acct.Name, Enabled: true, Root: true,
		AccessMode: "default", CreatedAt: now, UpdatedAt: now,
	}
	if err := s.users().Create(ctx, root.ID, root); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return nil
}

// userByName finds a user by exact name.
func (s *Service) userByName(ctx context.Context, name string) (user, bool, error) {
	found, err := s.users().List(ctx, func(u user) bool { return u.Name == name })
	if err != nil || len(found) == 0 {
		return user{}, false, err
	}
	return found[0], true, nil
}

func (s *Service) groupByName(ctx context.Context, name string) (group, bool, error) {
	found, err := s.groups().List(ctx, func(g group) bool { return g.Name == name })
	if err != nil || len(found) == 0 {
		return group{}, false, err
	}
	return found[0], true, nil
}

// groupsOf lists the groups userID belongs to.
func (s *Service) groupsOf(ctx context.Context, userID string) ([]group, error) {
	return s.groups().List(ctx, func(g group) bool { return g.has(userID) })
}

// deleteUser removes a user and its group memberships. The caller holds
// s.mu.
func (s *Service) deleteUser(ctx context.Context, id string) error {
	in, err := s.groupsOf(ctx, id)
	if err != nil {
		return err
	}
	for _, g := range in {
		_, err := s.groups().Update(ctx, g.ID, func(g *group) error {
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == id })
			return nil
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return s.users().Delete(ctx, id)
}

// countUsers counts IAM users, the root user not included.
func (s *Service) countUsers(ctx context.Context) (int, error) {
	all, err := s.users().List(ctx, func(u user) bool { return !u.Root })
	return len(all), err
}

// Name and text rules, from Huawei's documentation of IAM's constraints.
var (
	// A username has at most 64 characters: letters, digits, spaces, "-",
	// "_" and "."; it does not start with a digit or a space.
	usernameRE = regexp.MustCompile(`^[\p{L}\-_.][\p{L}0-9 \-_.]{0,63}$`)
	// A group name has at most 128 characters: letters, digits, spaces,
	// "-" and "_".
	groupNameRE = regexp.MustCompile(`^[\p{L}0-9 \-_]{1,128}$`)
	emailRE     = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	digitsRE    = regexp.MustCompile(`^[0-9]{1,32}$`)
)

// validDescription: at most 255 characters, none of @#%&<>\$^*.
func validDescription(d string) bool {
	return utf8.RuneCountInString(d) <= 255 && !strings.ContainsAny(d, `@#%&<>\$^*`)
}

func validAccessMode(m string) bool {
	return m == "default" || m == "console" || m == "programmatic"
}

// Passwords.
//
// Documented: a password may not be the username or the username
// reversed. Assumed, not verified against Huawei's documentation: the
// default password policy's 8 to 32 characters with at least two of
// lowercase letters, uppercase letters, digits and special characters.
const (
	minPasswordLen = 8
	maxPasswordLen = 32
)

func strongEnough(password, username string) bool {
	n := utf8.RuneCountInString(password)
	if n < minPasswordLen || n > maxPasswordLen {
		return false
	}
	if strings.EqualFold(password, username) || strings.EqualFold(password, reverse(username)) {
		return false
	}
	var lower, upper, digit, special bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsSpace(r) || !unicode.IsPrint(r):
			return false
		default:
			special = true
		}
	}
	kinds := 0
	for _, b := range []bool{lower, upper, digit, special} {
		if b {
			kinds++
		}
	}
	return kinds >= 2
}

func reverse(s string) string {
	r := []rune(s)
	slices.Reverse(r)
	return string(r)
}

// passwordHash is PBKDF2-SHA256. The iteration count is modest: this
// guards test passwords against a casual look at the data file, and logins
// must stay fast in tests.
type passwordHash struct {
	Salt       []byte `json:"salt"`
	Iterations int    `json:"iterations"`
	Hash       []byte `json:"hash"`
}

const pbkdf2Iterations = 10_000

func hashPassword(password string) (*passwordHash, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return nil, err
	}
	return &passwordHash{Salt: salt, Iterations: pbkdf2Iterations, Hash: h}, nil
}

func (p *passwordHash) matches(password string) bool {
	if p == nil {
		return false
	}
	h, err := pbkdf2.Key(sha256.New, password, p.Salt, p.Iterations, len(p.Hash))
	return err == nil && subtle.ConstantTimeCompare(h, p.Hash) == 1
}

// setPassword checks and stores a new password for u.
func (u *user) setPassword(password string, now time.Time) error {
	if !strongEnough(password, u.Name) {
		return errWeakPassword
	}
	h, err := hashPassword(password)
	if err != nil {
		return err
	}
	u.Password, u.PasswordChangedAt = h, now
	return nil
}
