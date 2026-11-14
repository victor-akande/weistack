package iam

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// IAM 5.0 users and groups (/v5), over the same records as classic IAM.

// v5Time is the format of IAM 5.0 timestamps.
const v5Time = "2006-01-02T15:04:05.000Z"

func v5At(t time.Time) string { return t.UTC().Format(v5Time) }

// urn names a resource the IAM 5.0 way, as in Huawei's examples:
// "iam::<account-id>:user:<name>".
func (s *Service) urn(kind, name string) string {
	return "iam::" + s.account().ID + ":" + kind + ":" + name
}

// v5UserView mirrors the SDK model iam/v5 User.
type v5UserView struct {
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	Description string `json:"description"`
	IsRootUser  bool   `json:"is_root_user"`
	Enabled     bool   `json:"enabled"`
	URN         string `json:"urn"`
	CreatedAt   string `json:"created_at"`
}

func (s *Service) v5User(u user) v5UserView {
	return v5UserView{
		UserID: u.ID, UserName: u.Name, Description: u.Description, IsRootUser: u.Root, Enabled: u.Enabled,
		URN: s.urn("user", u.Name), CreatedAt: v5At(u.CreatedAt),
	}
}

// v5GroupView mirrors the SDK model iam/v5 Group.
type v5GroupView struct {
	GroupID     string `json:"group_id"`
	GroupName   string `json:"group_name"`
	Description string `json:"description"`
	URN         string `json:"urn"`
	CreatedAt   string `json:"created_at"`
}

func (s *Service) v5Group(g group) v5GroupView {
	return v5GroupView{GroupID: g.ID, GroupName: g.Name, Description: g.Description, URN: s.urn("group", g.Name), CreatedAt: v5At(g.CreatedAt)}
}

type pageInfo struct {
	NextMarker   string `json:"next_marker,omitempty"`
	CurrentCount int    `json:"current_count"`
}

// page cuts one page from all, after the marker: the ID of the first
// item of the page, as handed out in next_marker. limit is 1 to 200,
// 100 by default.
func page[T any](r *http.Request, all []T, id func(T) string) ([]T, pageInfo, error) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			return nil, pageInfo{}, errV5Input
		}
		limit = n
	}
	start := 0
	if m := q.Get("marker"); m != "" {
		start = slices.IndexFunc(all, func(v T) bool { return id(v) == m })
		if start < 0 {
			return nil, pageInfo{}, errV5Marker
		}
	}
	end := min(start+limit, len(all))
	info := pageInfo{CurrentCount: end - start}
	if end < len(all) {
		info.NextMarker = id(all[end])
	}
	return all[start:end], info, nil
}

func decodeV5(r *http.Request, dst any) error {
	if err := httpx.DecodeJSON(r, dst); err != nil {
		return errV5Input.WithCause(err)
	}
	return nil
}

// fromClassic turns a classic validation error into IAM 5.0's.
func fromClassic(err error) error {
	var e *apierr.Error
	switch {
	case errors.Is(err, errUsernameTaken):
		return errV5UserExists
	case errors.Is(err, errTooManyUsers):
		return err // IAM 5.0 documents no code for its user quota
	case errors.As(err, &e) && e.Status == http.StatusBadRequest:
		return errV5Input.WithCause(err)
	case errors.As(err, &e) && e.Status == http.StatusForbidden:
		return errV5Denied("the root user cannot be renamed or disabled")
	}
	return err
}

type v5UserResponse struct {
	User v5UserView `json:"user"`
}

// POST /v5/users.
func (s *Service) handleCreateUserV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Enabled     *bool   `json:"enabled"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	u, err := s.createUser(r, userChange{Name: b.Name, Description: b.Description, Enabled: b.Enabled}, errV5Input)
	if err != nil {
		return fromClassic(err)
	}
	return httpx.WriteJSON(w, http.StatusCreated, v5UserResponse{s.v5User(u)})
}

type v5UsersResponse struct {
	Users    []v5UserView `json:"users"`
	PageInfo pageInfo     `json:"page_info"`
}

// GET /v5/users, optionally the members of group_id or the owner of
// access_key_id. Service-specific credentials are not emulated, so a
// lookup by one finds no one.
func (s *Service) handleListUsersV5(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	keep := func(user) bool { return true }
	switch {
	case q.Get("access_key_id") != "":
		k, err := s.accessKeys().Get(r.Context(), q.Get("access_key_id"))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		keep = func(u user) bool { return err == nil && u.ID == k.UserID }
	case q.Get("service_specific_credential_id") != "":
		keep = func(user) bool { return false }
	case q.Get("group_id") != "":
		g, err := s.groups().Get(r.Context(), q.Get("group_id"))
		if errors.Is(err, store.ErrNotFound) {
			return errV5NoGroup
		}
		if err != nil {
			return err
		}
		keep = func(u user) bool { return g.has(u.ID) }
	}
	all, err := s.users().List(r.Context(), keep)
	if err != nil {
		return err
	}
	got, info, err := page(r, all, func(u user) string { return u.ID })
	if err != nil {
		return err
	}
	out := v5UsersResponse{Users: make([]v5UserView, 0, len(got)), PageInfo: info}
	for _, u := range got {
		out.Users = append(out.Users, s.v5User(u))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) getUserV5(r *http.Request) (user, error) {
	u, err := s.users().Get(r.Context(), chi.URLParam(r, "user_id"))
	if errors.Is(err, store.ErrNotFound) {
		return user{}, errV5NoUser
	}
	return u, err
}

func (s *Service) handleShowUserV5(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUserV5(r)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v5UserResponse{s.v5User(u)})
}

// PUT /v5/users/{user_id}.
func (s *Service) handleUpdateUserV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		NewUserName    *string `json:"new_user_name"`
		NewDescription *string `json:"new_description"`
		Enabled        *bool   `json:"enabled"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	u, err := s.updateUser(r, userChange{Name: b.NewUserName, Description: b.NewDescription, Enabled: b.Enabled})
	var e *apierr.Error
	if errors.As(err, &e) && e.Code == "IAM.0004" {
		return errV5NoUser
	}
	if err != nil {
		return fromClassic(err)
	}
	return httpx.WriteJSON(w, http.StatusOK, v5UserResponse{s.v5User(u)})
}

// DELETE /v5/users/{user_id}.
func (s *Service) handleDeleteUserV5(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUserV5(r)
	if err != nil {
		return err
	}
	if u.Root {
		return errV5DeleteConflict("the root user cannot be deleted")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.deleteUser(r.Context(), u.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type lastLoginView struct {
	LastLoginAt string `json:"last_login_at,omitempty"`
}

// GET /v5/users/{user_id}/last-login: when the user last signed in with
// a password; empty if never. Terraform reads it.
func (s *Service) handleShowUserLastLoginV5(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUserV5(r)
	if err != nil {
		return err
	}
	var v lastLoginView
	if !u.LastLoginAt.IsZero() {
		v.LastLoginAt = v5At(u.LastLoginAt)
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		UserLastLogin lastLoginView `json:"user_last_login"`
	}{v})
}

var v5GroupErrs = groupErrs{
	taken:    func(string) error { return errV5GroupExists },
	notFound: func(string) error { return errV5NoGroup },
}

type v5GroupResponse struct {
	Group v5GroupView `json:"group"`
}

func validGroupFields(name, description *string) bool {
	return (name == nil || validGroupName(*name)) && (description == nil || validDescription(*description))
}

// POST /v5/groups.
func (s *Service) handleCreateGroupV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		GroupName   *string `json:"group_name"`
		Description *string `json:"description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.GroupName == nil || !validGroupFields(b.GroupName, b.Description) {
		return errV5Input
	}
	g, err := s.createGroup(r, *b.GroupName, deref(b.Description), v5GroupErrs)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, v5GroupResponse{s.v5Group(g)})
}

type v5GroupsResponse struct {
	Groups   []v5GroupView `json:"groups"`
	PageInfo pageInfo      `json:"page_info"`
}

// GET /v5/groups, optionally those user_id belongs to.
func (s *Service) handleListGroupsV5(w http.ResponseWriter, r *http.Request) error {
	keep := func(group) bool { return true }
	if id := r.URL.Query().Get("user_id"); id != "" {
		if _, err := s.users().Get(r.Context(), id); errors.Is(err, store.ErrNotFound) {
			return errV5NoUser
		} else if err != nil {
			return err
		}
		keep = func(g group) bool { return g.has(id) }
	}
	all, err := s.groups().List(r.Context(), keep)
	if err != nil {
		return err
	}
	got, info, err := page(r, all, func(g group) string { return g.ID })
	if err != nil {
		return err
	}
	out := v5GroupsResponse{Groups: make([]v5GroupView, 0, len(got)), PageInfo: info}
	for _, g := range got {
		out.Groups = append(out.Groups, s.v5Group(g))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) handleShowGroupV5(w http.ResponseWriter, r *http.Request) error {
	g, err := s.getGroup(r, v5GroupErrs)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v5GroupResponse{s.v5Group(g)})
}

// PUT /v5/groups/{group_id}.
func (s *Service) handleUpdateGroupV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		NewGroupName        *string `json:"new_group_name"`
		NewGroupDescription *string `json:"new_group_description"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if !validGroupFields(b.NewGroupName, b.NewGroupDescription) {
		return errV5Input
	}
	g, err := s.updateGroup(r, b.NewGroupName, b.NewGroupDescription, v5GroupErrs)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v5GroupResponse{s.v5Group(g)})
}

func (s *Service) handleDeleteGroupV5(w http.ResponseWriter, r *http.Request) error {
	if err := s.deleteGroup(r, v5GroupErrs); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// POST /v5/groups/{group_id}/add-user and remove-user.
func (s *Service) v5Membership(member bool) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		var b struct {
			UserID string `json:"user_id"`
		}
		if err := decodeV5(r, &b); err != nil {
			return err
		}
		if b.UserID == "" {
			return errV5Input
		}
		errSame := error(errV5InGroup)
		if !member {
			errSame = errV5NoUser // not a member of this group
		}
		err := s.setMember(r, b.UserID, member,
			func() error { return errV5NoGroup }, func() error { return errV5NoUser }, errSame)
		if err != nil {
			return err
		}
		// 200, as documented: Terraform's group membership accepts no 204.
		w.WriteHeader(http.StatusOK)
		return nil
	}
}
