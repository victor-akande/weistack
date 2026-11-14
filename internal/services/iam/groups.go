package iam

import (
	"errors"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Classic IAM groups: Keystone's /v3/groups.

// groupView mirrors the SDK models KeystoneGroupResult and
// KeystoneGroupResultWithLinksSelf. create_time is in milliseconds.
type groupView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	DomainID    string `json:"domain_id"`
	CreateTime  int64  `json:"create_time"`
	Links       links  `json:"links"`
}

type groupResponse struct {
	Group groupView `json:"group"`
}

func (s *Service) groupView(r *http.Request, g group) groupView {
	return groupView{
		ID: g.ID, Name: g.Name, Description: g.Description, DomainID: s.account().ID,
		CreateTime: g.CreatedAt.UnixMilli(), Links: selfLinks(r, "/v3/groups/"+g.ID),
	}
}

func (s *Service) writeGroups(w http.ResponseWriter, r *http.Request, path string, all []group) error {
	out := groupsResponse{Groups: make([]groupView, 0, len(all)), Links: selfLinks(r, path)}
	for _, g := range all {
		out.Groups = append(out.Groups, s.groupView(r, g))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

type groupChange struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	DomainID    *string `json:"domain_id"`
}

func readGroupBody(r *http.Request) (groupChange, error) {
	var b struct {
		Group *groupChange `json:"group"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return groupChange{}, err
	}
	if b.Group == nil {
		return groupChange{}, errRequired("group")
	}
	return *b.Group, nil
}

// checkGroupChange validates the fields given, classic style.
func (s *Service) checkGroupChange(c groupChange) error {
	if c.DomainID != nil && *c.DomainID != s.account().ID {
		return errInvalidField("domain_id", *c.DomainID)
	}
	if c.Name != nil && !validGroupName(*c.Name) {
		return errInvalidField("name", *c.Name)
	}
	if c.Description != nil && !validDescription(*c.Description) {
		return errInvalidField("description", *c.Description)
	}
	return nil
}

// groupErrs are the errors each API reports for a name in use and a
// missing group.
type groupErrs struct {
	taken    func(name string) error
	notFound func(id string) error
}

var classicGroupErrs = groupErrs{
	taken:    func(name string) error { return errConflict("group", "a group named "+name+" already exists") },
	notFound: func(id string) error { return errNotFound("group", id) },
}

// createGroup stores a new group. The caller has validated name and
// description.
func (s *Service) createGroup(r *http.Request, name, description string, e groupErrs) (group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken, err := s.groupByName(r.Context(), name); err != nil || taken {
		if err == nil {
			err = e.taken(name)
		}
		return group{}, err
	}
	g := group{ID: s.ids.Hex32(), Name: name, Description: description, CreatedAt: s.now().UTC()}
	return g, s.groups().Create(r.Context(), g.ID, g)
}

// updateGroup renames or redescribes the group in the path.
func (s *Service) updateGroup(r *http.Request, name, description *string, e groupErrs) (group, error) {
	id := chi.URLParam(r, "group_id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if name != nil {
		if other, taken, err := s.groupByName(r.Context(), *name); err != nil || (taken && other.ID != id) {
			if err == nil {
				err = e.taken(*name)
			}
			return group{}, err
		}
	}
	g, err := s.groups().Update(r.Context(), id, func(g *group) error {
		if name != nil {
			g.Name = *name
		}
		if description != nil {
			g.Description = *description
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return group{}, e.notFound(id)
	}
	return g, err
}

func (s *Service) getGroup(r *http.Request, e groupErrs) (group, error) {
	id := chi.URLParam(r, "group_id")
	g, err := s.groups().Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return group{}, e.notFound(id)
	}
	return g, err
}

func (s *Service) deleteGroup(r *http.Request, e groupErrs) error {
	id := chi.URLParam(r, "group_id")
	err := s.groups().Delete(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return e.notFound(id)
	}
	return err
}

// setMember adds userID to, or removes it from, the group in the path.
// It fails if the group or user does not exist, or if the membership is
// already as asked (errSame).
func (s *Service) setMember(r *http.Request, userID string, member bool, noGroup, noUser func() error, errSame error) error {
	groupID := chi.URLParam(r, "group_id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.users().Get(r.Context(), userID); errors.Is(err, store.ErrNotFound) {
		return noUser()
	} else if err != nil {
		return err
	}
	_, err := s.groups().Update(r.Context(), groupID, func(g *group) error {
		if g.has(userID) == member {
			return errSame
		}
		if member {
			g.Members = append(g.Members, userID)
		} else {
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == userID })
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return noGroup()
	}
	return err
}

// POST /v3/groups.
func (s *Service) handleCreateGroup(w http.ResponseWriter, r *http.Request) error {
	c, err := readGroupBody(r)
	if err != nil {
		return err
	}
	if c.Name == nil {
		return errRequired("name")
	}
	if err := s.checkGroupChange(c); err != nil {
		return err
	}
	g, err := s.createGroup(r, *c.Name, deref(c.Description), classicGroupErrs)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, groupResponse{s.groupView(r, g)})
}

// GET /v3/groups, filtered by name and domain_id.
func (s *Service) handleListGroups(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	if d := q.Get("domain_id"); d != "" && d != s.account().ID {
		return s.writeGroups(w, r, "/v3/groups", nil)
	}
	all, err := s.groups().List(r.Context(), func(g group) bool { return q.Get("name") == "" || g.Name == q.Get("name") })
	if err != nil {
		return err
	}
	return s.writeGroups(w, r, "/v3/groups", all)
}

func (s *Service) handleShowGroup(w http.ResponseWriter, r *http.Request) error {
	g, err := s.getGroup(r, classicGroupErrs)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, groupResponse{s.groupView(r, g)})
}

// PATCH /v3/groups/{group_id}.
func (s *Service) handleUpdateGroup(w http.ResponseWriter, r *http.Request) error {
	c, err := readGroupBody(r)
	if err != nil {
		return err
	}
	if err := s.checkGroupChange(c); err != nil {
		return err
	}
	g, err := s.updateGroup(r, c.Name, c.Description, classicGroupErrs)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, groupResponse{s.groupView(r, g)})
}

// DELETE /v3/groups/{group_id}. Its members stay, outside the group.
func (s *Service) handleDeleteGroup(w http.ResponseWriter, r *http.Request) error {
	if err := s.deleteGroup(r, classicGroupErrs); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// GET /v3/groups/{group_id}/users.
func (s *Service) handleListUsersInGroup(w http.ResponseWriter, r *http.Request) error {
	g, err := s.getGroup(r, classicGroupErrs)
	if err != nil {
		return err
	}
	members, err := s.users().List(r.Context(), func(u user) bool { return g.has(u.ID) })
	if err != nil {
		return err
	}
	return s.writeUsers(w, r, "/v3/groups/"+g.ID+"/users", members)
}

// errAlreadyMember marks a classic add of an existing member, which
// succeeds without change.
var errAlreadyMember = errors.New("already a member")

// PUT /v3/groups/{group_id}/users/{user_id}. Adding a member again
// succeeds, as in Keystone.
func (s *Service) handleAddUserToGroup(w http.ResponseWriter, r *http.Request) error {
	userID := chi.URLParam(r, "user_id")
	err := s.setMember(r, userID, true,
		func() error { return errNotFound("group", chi.URLParam(r, "group_id")) },
		func() error { return errNotFound("user", userID) },
		errAlreadyMember)
	if err != nil && !errors.Is(err, errAlreadyMember) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// HEAD /v3/groups/{group_id}/users/{user_id}: 204 for a member, 404
// otherwise.
func (s *Service) handleCheckUserInGroup(w http.ResponseWriter, r *http.Request) error {
	g, err := s.getGroup(r, classicGroupErrs)
	if err != nil {
		return err
	}
	userID := chi.URLParam(r, "user_id")
	if !g.has(userID) {
		return errNotFound("user", userID)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// DELETE /v3/groups/{group_id}/users/{user_id}.
func (s *Service) handleRemoveUserFromGroup(w http.ResponseWriter, r *http.Request) error {
	userID := chi.URLParam(r, "user_id")
	err := s.setMember(r, userID, false,
		func() error { return errNotFound("group", chi.URLParam(r, "group_id")) },
		func() error { return errNotFound("user", userID) },
		errNotFound("user", userID))
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
