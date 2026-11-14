package iam

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Classic IAM users: Keystone's /v3/users and Huawei's /v3.0/OS-USER.

// osUserTime is the format of OS-USER's create_time, as in Huawei's
// examples ("2020-07-08 02:19:03.0").
const osUserTime = "2006-01-02 15:04:05.0"

// keystoneUserView mirrors the SDK models KeystoneShowUserResult,
// KeystoneListUsersResult and KeystoneCreateUserResult.
type keystoneUserView struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	DomainID          string  `json:"domain_id"`
	Description       string  `json:"description"`
	Enabled           bool    `json:"enabled"`
	PwdStatus         bool    `json:"pwd_status"`
	PasswordExpiresAt *string `json:"password_expires_at"`
	AccessMode        string  `json:"access_mode,omitempty"`
	Links             links   `json:"links"`
}

// osUserView mirrors the SDK models CreateUserResult, ShowUserResult and
// UpdateUserResult.
type osUserView struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	DomainID          string  `json:"domain_id"`
	Description       string  `json:"description"`
	Enabled           bool    `json:"enabled"`
	AccessMode        string  `json:"access_mode"`
	Email             string  `json:"email,omitempty"`
	AreaCode          string  `json:"areacode,omitempty"`
	Phone             string  `json:"phone,omitempty"`
	PwdStatus         bool    `json:"pwd_status"`
	IsDomainOwner     bool    `json:"is_domain_owner"`
	CreateTime        string  `json:"create_time"`
	UpdateTime        string  `json:"update_time,omitempty"`
	LastLoginTime     string  `json:"last_login_time,omitempty"`
	PasswordExpiresAt *string `json:"password_expires_at"`
	Links             links   `json:"links"`
}

type userResponse[V any] struct {
	User V `json:"user"`
}

func (s *Service) keystoneView(r *http.Request, u user) keystoneUserView {
	return keystoneUserView{
		ID: u.ID, Name: u.Name, DomainID: s.account().ID, Description: u.Description, Enabled: u.Enabled,
		PwdStatus: u.PwdStatus, AccessMode: u.AccessMode, Links: selfLinks(r, "/v3/users/"+u.ID),
	}
}

func (s *Service) osView(r *http.Request, u user) osUserView {
	v := osUserView{
		ID: u.ID, Name: u.Name, DomainID: s.account().ID, Description: u.Description, Enabled: u.Enabled,
		AccessMode: u.AccessMode, Email: u.Email, AreaCode: u.AreaCode, Phone: u.Phone, PwdStatus: u.PwdStatus,
		IsDomainOwner: u.Root, CreateTime: u.CreatedAt.UTC().Format(osUserTime),
		UpdateTime: u.UpdatedAt.UTC().Format(osUserTime), Links: selfLinks(r, "/v3.0/OS-USER/users/"+u.ID),
	}
	if !u.LastLoginAt.IsZero() {
		v.LastLoginTime = u.LastLoginAt.UTC().Format(osUserTime)
	}
	return v
}

func selfLinks(r *http.Request, path string) links { return links{Self: selfURL(r, path)} }

// userChange is the union of the fields the classic user operations set.
// Nil means "not given".
type userChange struct {
	Name        *string `json:"name"`
	DomainID    *string `json:"domain_id"`
	Password    *string `json:"password"`
	Description *string `json:"description"`
	Enabled     *bool   `json:"enabled"`
	AccessMode  *string `json:"access_mode"`
	Email       *string `json:"email"`
	AreaCode    *string `json:"areacode"`
	Phone       *string `json:"phone"`
	PwdStatus   *bool   `json:"pwd_status"`
}

// apply validates c and applies it to u. Name uniqueness is the caller's.
func (s *Service) apply(c userChange, u *user, now time.Time) error {
	if c.DomainID != nil && *c.DomainID != s.account().ID {
		return errInvalidField("domain_id", *c.DomainID)
	}
	if c.Name != nil {
		if !validUsername(*c.Name) {
			return errBadUsername
		}
		if u.Root && *c.Name != u.Name {
			return errForbidden()
		}
		u.Name = *c.Name
	}
	if c.Description != nil {
		if !validDescription(*c.Description) {
			return errBadDescription
		}
		u.Description = *c.Description
	}
	if c.Enabled != nil {
		if u.Root && !*c.Enabled {
			return errForbidden()
		}
		u.Enabled = *c.Enabled
	}
	if c.AccessMode != nil {
		if !validAccessMode(*c.AccessMode) {
			return errBadAccessMode
		}
		u.AccessMode = *c.AccessMode
	}
	if c.Email != nil {
		if *c.Email != "" && !emailRE.MatchString(*c.Email) {
			return errBadEmail
		}
		u.Email = *c.Email
	}
	if (c.AreaCode == nil) != (c.Phone == nil) {
		return errPhonePair
	}
	if c.Phone != nil {
		if (*c.Phone == "") != (*c.AreaCode == "") {
			return errPhonePair
		}
		if *c.Phone != "" && (!digitsRE.MatchString(*c.Phone) || !digitsRE.MatchString(*c.AreaCode)) {
			return errBadPhone
		}
		u.AreaCode, u.Phone = *c.AreaCode, *c.Phone
	}
	if c.PwdStatus != nil {
		u.PwdStatus = *c.PwdStatus
	}
	if c.Password != nil {
		if err := u.setPassword(*c.Password, now); err != nil {
			return err
		}
	}
	u.UpdatedAt = now
	return nil
}

// createUser stores a new user from c. mandatory is the error for a
// missing name.
func (s *Service) createUser(r *http.Request, c userChange, mandatory error) (user, error) {
	if c.Name == nil || *c.Name == "" {
		return user{}, mandatory
	}
	now := s.now().UTC()
	u := user{ID: s.ids.Hex32(), Enabled: true, AccessMode: "default", CreatedAt: now}
	if err := s.apply(c, &u, now); err != nil {
		return user{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	if _, taken, err := s.userByName(ctx, u.Name); err != nil || taken {
		if err == nil {
			err = errUsernameTaken
		}
		return user{}, err
	}
	if n, err := s.countUsers(ctx); err != nil || n >= maxUsers {
		if err == nil {
			err = errTooManyUsers
		}
		return user{}, err
	}
	return u, s.users().Create(ctx, u.ID, u)
}

// updateUser applies c to the user named in the path.
func (s *Service) updateUser(r *http.Request, c userChange) (user, error) {
	id := chi.URLParam(r, "user_id")
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := r.Context()
	if c.Name != nil {
		if other, taken, err := s.userByName(ctx, *c.Name); err != nil || (taken && other.ID != id) {
			if err == nil {
				err = errUsernameTaken
			}
			return user{}, err
		}
	}
	now := s.now().UTC()
	u, err := s.users().Update(ctx, id, func(u *user) error { return s.apply(c, u, now) })
	if errors.Is(err, store.ErrNotFound) {
		return user{}, errNotFound("user", id)
	}
	if err != nil {
		return user{}, err
	}
	// The user's keys now act under the new name.
	return u, s.registerKeysOf(ctx, u)
}

func (s *Service) getUser(r *http.Request) (user, error) {
	id := chi.URLParam(r, "user_id")
	u, err := s.users().Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return user{}, errNotFound("user", id)
	}
	return u, err
}

// decodeClassic reads a request body into dst, as classic IAM reports it.
func decodeClassic(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errBadBody().WithCause(err)
	}
	return nil
}

type userBody struct {
	User *userChange `json:"user"`
}

func readUserBody(r *http.Request) (userChange, error) {
	var b userBody
	if err := decodeClassic(r, &b); err != nil {
		return userChange{}, err
	}
	if b.User == nil {
		return userChange{}, errRequired("user")
	}
	return *b.User, nil
}

// POST /v3.0/OS-USER/users: Huawei's recommended create, which Terraform
// uses. domain_id is mandatory.
func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) error {
	c, err := readUserBody(r)
	if err != nil {
		return err
	}
	if c.DomainID == nil {
		return errMandatory
	}
	u, err := s.createUser(r, c, errMandatory)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, userResponse[osUserView]{s.osView(r, u)})
}

func (s *Service) handleShowUser(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUser(r)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, userResponse[osUserView]{s.osView(r, u)})
}

// PUT /v3.0/OS-USER/users/{user_id}.
func (s *Service) handleUpdateUser(w http.ResponseWriter, r *http.Request) error {
	c, err := readUserBody(r)
	if err != nil {
		return err
	}
	u, err := s.updateUser(r, c)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, userResponse[osUserView]{s.osView(r, u)})
}

// PUT /v3.0/OS-USER/users/{user_id}/info: a user's own email and mobile
// number, the mobile as "<country code>-<number>".
func (s *Service) handleUpdateUserInformation(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		User *struct {
			Email  *string `json:"email"`
			Mobile *string `json:"mobile"`
		} `json:"user"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	if b.User == nil {
		return errRequired("user")
	}
	c := userChange{Email: b.User.Email}
	if m := b.User.Mobile; m != nil {
		code, number, ok := strings.Cut(*m, "-")
		if !ok && *m != "" {
			return errBadPhone
		}
		c.AreaCode, c.Phone = &code, &number
	}
	if _, err := s.updateUser(r, c); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// POST /v3/users.
func (s *Service) handleKeystoneCreateUser(w http.ResponseWriter, r *http.Request) error {
	c, err := readUserBody(r)
	if err != nil {
		return err
	}
	u, err := s.createUser(r, c, errRequired("name"))
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, userResponse[keystoneUserView]{s.keystoneView(r, u)})
}

type listUsersResponse struct {
	Users []keystoneUserView `json:"users"`
	Links links              `json:"links"`
}

// GET /v3/users, filtered by name, enabled and domain_id.
func (s *Service) handleKeystoneListUsers(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	enabled := q.Get("enabled")
	if enabled != "" && enabled != "true" && enabled != "false" {
		return errInvalidParam("enabled")
	}
	if d := q.Get("domain_id"); d != "" && d != s.account().ID {
		return s.writeUsers(w, r, "/v3/users", nil)
	}
	all, err := s.users().List(r.Context(), func(u user) bool {
		return (q.Get("name") == "" || u.Name == q.Get("name")) && (enabled == "" || (enabled == "true") == u.Enabled)
	})
	if err != nil {
		return err
	}
	return s.writeUsers(w, r, "/v3/users", all)
}

func (s *Service) writeUsers(w http.ResponseWriter, r *http.Request, path string, all []user) error {
	out := listUsersResponse{Users: make([]keystoneUserView, 0, len(all)), Links: selfLinks(r, path)}
	for _, u := range all {
		out.Users = append(out.Users, s.keystoneView(r, u))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) handleKeystoneShowUser(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUser(r)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, userResponse[keystoneUserView]{s.keystoneView(r, u)})
}

// PATCH /v3/users/{user_id}.
func (s *Service) handleKeystoneUpdateUser(w http.ResponseWriter, r *http.Request) error {
	c, err := readUserBody(r)
	if err != nil {
		return err
	}
	// Keystone's update sets only these.
	c = userChange{Name: c.Name, DomainID: c.DomainID, Password: c.Password, Description: c.Description, Enabled: c.Enabled, PwdStatus: c.PwdStatus}
	u, err := s.updateUser(r, c)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, userResponse[keystoneUserView]{s.keystoneView(r, u)})
}

// DELETE /v3/users/{user_id}.
func (s *Service) handleKeystoneDeleteUser(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUser(r)
	if err != nil {
		return err
	}
	if u.Root {
		return errDeleteRoot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.deleteUser(r.Context(), u.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// POST /v3/users/{user_id}/password: a user changes their own password,
// giving the current one.
func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		User *struct {
			Password         *string `json:"password"`
			OriginalPassword *string `json:"original_password"`
		} `json:"user"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	switch {
	case b.User == nil:
		return errRequired("user")
	case b.User.Password == nil:
		return errRequired("password")
	case b.User.OriginalPassword == nil:
		return errRequired("original_password")
	}
	id := chi.URLParam(r, "user_id")
	now := s.now().UTC()
	_, err := s.users().Update(r.Context(), id, func(u *user) error {
		if !u.Password.matches(*b.User.OriginalPassword) {
			return errWrongPassword
		}
		if *b.User.Password == *b.User.OriginalPassword {
			return errSamePassword
		}
		u.PwdStatus = false
		return u.setPassword(*b.User.Password, now)
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("user", id)
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type groupsResponse struct {
	Groups []groupView `json:"groups"`
	Links  links       `json:"links"`
}

// GET /v3/users/{user_id}/groups.
func (s *Service) handleListGroupsForUser(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUser(r)
	if err != nil {
		return err
	}
	in, err := s.groupsOf(r.Context(), u.ID)
	if err != nil {
		return err
	}
	return s.writeGroups(w, r, "/v3/users/"+u.ID+"/groups", in)
}

// GET /v3/users/{user_id}/projects: the projects a user may use. The root
// user may use them all; others gain projects through role assignments,
// which are not emulated yet.
func (s *Service) handleListProjectsForUser(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUser(r)
	if err != nil {
		return err
	}
	out := listProjectsResponse{Projects: []projectView{}, Links: selfLinks(r, "/v3/users/"+u.ID+"/projects")}
	if u.Root {
		all, err := s.projects().List(r.Context(), nil)
		if err != nil {
			return err
		}
		for _, p := range all {
			out.Projects = append(out.Projects, p.view(r))
		}
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

type loginProtectView struct {
	Enabled            bool   `json:"enabled"`
	UserID             string `json:"user_id"`
	VerificationMethod string `json:"verification_method"`
}

type loginProtectResponse struct {
	LoginProtect loginProtectView `json:"login_protect"`
}

func protectView(u user) loginProtectResponse {
	m := u.LoginProtect.Method
	if m == "" {
		m = "none"
	}
	return loginProtectResponse{loginProtectView{Enabled: u.LoginProtect.Enabled, UserID: u.ID, VerificationMethod: m}}
}

// GET /v3.0/OS-USER/users/{user_id}/login-protect. Terraform reads it on
// every refresh of a user.
func (s *Service) handleShowLoginProtect(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUser(r)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, protectView(u))
}

// PUT /v3.0/OS-USER/users/{user_id}/login-protect. The setting is kept;
// logins are not challenged.
func (s *Service) handleUpdateLoginProtect(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		LoginProtect *struct {
			Enabled            *bool   `json:"enabled"`
			VerificationMethod *string `json:"verification_method"`
		} `json:"login_protect"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	switch {
	case b.LoginProtect == nil:
		return errRequired("login_protect")
	case b.LoginProtect.Enabled == nil:
		return errRequired("enabled")
	case b.LoginProtect.VerificationMethod == nil:
		return errRequired("verification_method")
	}
	enabled, method := *b.LoginProtect.Enabled, *b.LoginProtect.VerificationMethod
	switch {
	case method == "sms" || method == "email" || method == "vmfa":
	case method == "none" && !enabled:
	default:
		return errInvalidField("verification_method", method)
	}
	id := chi.URLParam(r, "user_id")
	now := s.now().UTC()
	u, err := s.users().Update(r.Context(), id, func(u *user) error {
		u.LoginProtect, u.UpdatedAt = loginProtect{Enabled: enabled, Method: method}, now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("user", id)
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, protectView(u))
}
