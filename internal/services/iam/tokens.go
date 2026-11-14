package iam

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Tokens: POST /v3/auth/tokens issues one, by password or from another
// token, and GET /v3/auth/tokens validates one. The token itself travels
// in the X-Subject-Token header.
//
// Tokens live in memory: a restart or a reset ends them, and clients get
// a new one, as they do when one expires. A token also ends when its user
// is deleted or disabled, or changes password.

// tokenLifetime is IAM's: 24 hours.
const tokenLifetime = 24 * time.Hour

// keystoneTime is the format of a token's issued_at and expires_at.
const keystoneTime = "2006-01-02T15:04:05.000000Z"

type token struct {
	UserID    string
	Methods   []string
	ProjectID string // the project scope, if any
	Domain    bool   // the domain scope
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type tokens struct {
	mu sync.Mutex
	m  map[string]token
}

func (t *tokens) put(id string, tok token, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]token{}
	}
	for k, v := range t.m {
		if !now.Before(v.ExpiresAt) {
			delete(t.m, k)
		}
	}
	t.m[id] = tok
}

func (t *tokens) get(id string) (token, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tok, ok := t.m[id]
	return tok, ok
}

func (t *tokens) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m = nil
}

func newTokenID() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type nameID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type authRequest struct {
	Auth *struct {
		Identity *struct {
			Methods  []string `json:"methods"`
			Password *struct {
				User *passwordUser `json:"user"`
			} `json:"password"`
			Token *struct {
				ID string `json:"id"`
			} `json:"token"`
		} `json:"identity"`
		Scope *struct {
			Project *struct {
				nameID
				Domain *nameID `json:"domain"`
			} `json:"project"`
			Domain *nameID `json:"domain"`
		} `json:"scope"`
	} `json:"auth"`
}

// passwordUser names the user of a password login: by ID, or by name
// within the account.
type passwordUser struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Password *string `json:"password"`
	Domain   *nameID `json:"domain"`
}

// handleCreateToken is POST /v3/auth/tokens.
func (s *Service) handleCreateToken(w http.ResponseWriter, r *http.Request) error {
	var req authRequest
	if err := decodeClassic(r, &req); err != nil {
		return err
	}
	switch {
	case req.Auth == nil:
		return errRequired("auth")
	case req.Auth.Identity == nil:
		return errRequired("identity")
	}
	id := req.Auth.Identity
	now := s.now().UTC()
	var (
		u       user
		methods []string
		err     error
	)
	switch {
	case slices.Contains(id.Methods, "password"):
		if id.Password == nil || id.Password.User == nil {
			return errRequired("password")
		}
		u, err = s.passwordLogin(r, id.Password.User, now)
		methods = []string{"password"}
	case slices.Contains(id.Methods, "token"):
		if id.Token == nil || id.Token.ID == "" {
			return errRequired("token")
		}
		var from token
		from, u, err = s.liveToken(r, id.Token.ID, now)
		methods = from.Methods
		if !slices.Contains(methods, "token") {
			methods = append(slices.Clone(methods), "token")
		}
	default:
		return errInvalidField("methods", "")
	}
	if err != nil {
		return err
	}
	tok := token{UserID: u.ID, Methods: methods, IssuedAt: now, ExpiresAt: now.Add(tokenLifetime)}
	if sc := req.Auth.Scope; sc != nil {
		switch {
		case sc.Project != nil:
			p, err := s.scopeProject(r, sc.Project.nameID, sc.Project.Domain)
			if err != nil {
				return err
			}
			tok.ProjectID = p.ID
		case sc.Domain != nil:
			if !s.isAccount(*sc.Domain) {
				return errAuthRequired
			}
			tok.Domain = true
		}
	}
	tid, err := newTokenID()
	if err != nil {
		return err
	}
	s.tokens.put(tid, tok, now)
	return s.writeToken(w, r, http.StatusCreated, tid, tok, u)
}

func (s *Service) isAccount(d nameID) bool {
	acct := s.account()
	return (d.ID == "" || d.ID == acct.ID) && (d.Name == "" || d.Name == acct.Name) && (d.ID != "" || d.Name != "")
}

// passwordLogin checks a user's password and records the login.
func (s *Service) passwordLogin(r *http.Request, pu *passwordUser, now time.Time) (user, error) {
	if pu.Password == nil {
		return user{}, errRequired("password")
	}
	var (
		u     user
		found bool
		err   error
	)
	switch {
	case pu.ID != "":
		u, err = s.users().Get(r.Context(), pu.ID)
		found = err == nil
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		}
	case pu.Name != "":
		// A user is named within its account (domain).
		if pu.Domain == nil || !s.isAccount(*pu.Domain) {
			return user{}, errAuthRequired
		}
		u, found, err = s.userByName(r.Context(), pu.Name)
	default:
		return user{}, errRequired("name")
	}
	switch {
	case err != nil:
		return user{}, err
	case !found:
		return user{}, errAuthRequired
	case !u.Password.matches(*pu.Password):
		return user{}, errLoginPassword
	case !u.Enabled:
		return user{}, errUserDisabled(u.Name)
	case u.AccessMode == "console":
		return user{}, errConsoleOnly
	}
	u, err = s.users().Update(r.Context(), u.ID, func(u *user) error {
		u.LastLoginAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return user{}, errAuthRequired
	}
	return u, err
}

// liveToken returns a token and its user if the token is still good.
func (s *Service) liveToken(r *http.Request, id string, now time.Time) (token, user, error) {
	tok, ok := s.tokens.get(id)
	if !ok {
		return token{}, user{}, errTokenInvalid
	}
	if !now.Before(tok.ExpiresAt) {
		return token{}, user{}, errTokenExpired
	}
	u, err := s.users().Get(r.Context(), tok.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return token{}, user{}, errTokenInvalid
	case err != nil:
		return token{}, user{}, err
	case !u.Enabled || u.PasswordChangedAt.After(tok.IssuedAt):
		return token{}, user{}, errTokenInvalid
	}
	return tok, u, nil
}

// scopeProject finds the project a token asks for, by ID or by name
// (a region's name).
func (s *Service) scopeProject(r *http.Request, p nameID, domain *nameID) (project, error) {
	if domain != nil && !s.isAccount(*domain) {
		return project{}, errAuthRequired
	}
	if p.ID != "" {
		got, err := s.projects().Get(r.Context(), p.ID)
		if errors.Is(err, store.ErrNotFound) {
			return project{}, errNotFound("project", p.ID)
		}
		return got, err
	}
	if p.Name == "" {
		return project{}, errRequired("project")
	}
	if regionRE.MatchString(p.Name) {
		if err := s.ensureProject(r.Context(), p.Name); err != nil {
			return project{}, err
		}
	}
	found, err := s.projects().List(r.Context(), func(pr project) bool { return pr.Name == p.Name })
	if err != nil {
		return project{}, err
	}
	if len(found) == 0 {
		return project{}, errNotFound("project", p.Name)
	}
	return found[0], nil
}

// handleValidateToken is GET /v3/auth/tokens.
func (s *Service) handleValidateToken(w http.ResponseWriter, r *http.Request) error {
	id := r.Header.Get("X-Subject-Token")
	if id == "" {
		return errSubjectToken
	}
	tok, u, err := s.liveToken(r, id, s.now().UTC())
	if err != nil {
		return err
	}
	return s.writeToken(w, r, http.StatusOK, id, tok, u)
}

// tokenView mirrors the SDK model iam/v3 TokenResult.
type tokenView struct {
	Methods   []string       `json:"methods"`
	ExpiresAt string         `json:"expires_at"`
	IssuedAt  string         `json:"issued_at"`
	User      tokenUser      `json:"user"`
	Domain    *nameID        `json:"domain,omitempty"`
	Project   *tokenProject  `json:"project,omitempty"`
	Roles     []nameID       `json:"roles"`
	Catalog   *[]tokenTarget `json:"catalog,omitempty"`
}

type tokenUser struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Domain            nameID  `json:"domain"`
	PasswordExpiresAt *string `json:"password_expires_at"`
}

type tokenProject struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain nameID `json:"domain"`
}

// tokenTarget is a service catalog entry. The catalog is empty: clients
// of the emulator know their endpoints.
type tokenTarget struct{}

func (s *Service) writeToken(w http.ResponseWriter, r *http.Request, status int, id string, tok token, u user) error {
	acct := s.account()
	dom := nameID{ID: acct.ID, Name: acct.Name}
	v := tokenView{
		Methods: tok.Methods, ExpiresAt: tok.ExpiresAt.Format(keystoneTime), IssuedAt: tok.IssuedAt.Format(keystoneTime),
		User:  tokenUser{ID: u.ID, Name: u.Name, Domain: dom},
		Roles: []nameID{},
	}
	if r.URL.Query().Get("nocatalog") != "true" {
		v.Catalog = &[]tokenTarget{}
	}
	switch {
	case tok.ProjectID != "":
		p, err := s.projects().Get(r.Context(), tok.ProjectID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		v.Project = &tokenProject{ID: tok.ProjectID, Name: p.Name, Domain: dom}
	case tok.Domain:
		v.Domain = &dom
	}
	w.Header().Set("X-Subject-Token", id)
	return httpx.WriteJSON(w, status, struct {
		Token tokenView `json:"token"`
	}{v})
}
