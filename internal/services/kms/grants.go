package kms

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Grants (api-dew "Grant Management"): a key's owner lets a user, or
// another account (grantee_principal_type domain), use the key for some
// operations. A grant is a permission of its own: its grantee may
// perform them on the key without an IAM policy, also from another
// account, whose requests name the key by ID in their own project. The
// retiring principal, or a grantee allowed retire-grant, retires a
// grant; the owner revokes it.

const kindGrant = "kms.grant"

type grant struct {
	ID          string    `json:"id"`
	KeyID       string    `json:"key_id"`
	Grantee     string    `json:"grantee"`
	GranteeType string    `json:"grantee_type"`
	Operations  []string  `json:"operations"`
	Name        string    `json:"name,omitempty"`
	Retiring    string    `json:"retiring,omitempty"`
	Issuer      string    `json:"issuer"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Service) grants(region string) store.Collection[grant] {
	return store.Of[grant](s.store, store.Scope{Region: region, ProjectID: store.Global, Kind: kindGrant})
}

// grantOperations are the operations a grant may allow, by the action
// each checks.
var grantOperations = map[string]string{
	"kms:cmk:createDataKey":                 "create-datakey",
	"kms:cmk:createDataKeyWithoutPlaintext": "create-datakey-without-plaintext",
	"kms:cmk:encryptDataKey":                "encrypt-datakey",
	"kms:cmk:decryptDataKey":                "decrypt-datakey",
	"kms:cmk:get":                           "describe-key",
	"kms:cmk:createGrant":                   "create-grant",
	"kms:cmk:retireGrant":                   "retire-grant",
	"kms:cmk:encryptData":                   "encrypt-data",
	"kms:cmk:decryptData":                   "decrypt-data",
}

func validOperation(op string) bool {
	for _, o := range grantOperations {
		if o == op {
			return true
		}
	}
	return false
}

const (
	granteeUser   = "user"
	granteeDomain = "domain"
)

var (
	errGrantOps      = kmsErr(http.StatusBadRequest, "KMS.2401", "Specify an operation in addition to create-grant.")
	errGrantee       = kmsErr(http.StatusBadRequest, "KMS.2402", "Invalid user ID.")
	errKeyGrants     = kmsErr(http.StatusBadRequest, "KMS.2404", "Too many CMK grants.")
	errGrantID       = kmsErr(http.StatusBadRequest, "KMS.2501", "Invalid grant ID.")
	errGrantMismatch = kmsErr(http.StatusBadRequest, "KMS.2502", "grant_id and key_id do not match.")

	principalRE = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	grantIDRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validPrincipal(p string) bool { return len(p) >= 1 && len(p) <= 64 && principalRE.MatchString(p) }

// caller names who makes a request, for grants: its user (if any) and
// its account.
func (s *Service) caller(ctx context.Context) (userID, accountID string) {
	id := auth.FromContext(ctx)
	if id.Known {
		userID = id.Principal.UserID
	}
	return userID, s.account(ctx).ID
}

// covers reports whether a grant lets the caller perform op.
func (g grant) covers(userID, accountID, op string) bool {
	who := g.GranteeType == granteeUser && userID != "" && g.Grantee == userID ||
		g.GranteeType == granteeDomain && g.Grantee == accountID
	return who && slices.Contains(g.Operations, op)
}

// grantedKey returns the key with that ID, in any project or account,
// if a grant lets the caller perform the action's operation on it.
func (s *Service) grantedKey(ctx context.Context, t tenant, action, id string) (key, bool) {
	op, ok := grantOperations[action]
	if !ok || !keyIDRE.MatchString(id) {
		return key{}, false
	}
	k, err := s.keys(t.Region).Get(ctx, id)
	if err != nil || s.gone(k) {
		return key{}, false
	}
	userID, accountID := s.caller(ctx)
	gs, err := s.grants(t.Region).List(ctx, func(g grant) bool { return g.KeyID == id && g.covers(userID, accountID, op) })
	if err != nil || len(gs) == 0 {
		return key{}, false
	}
	return k, true
}

// keyGrants returns a key's grants, oldest first.
func (s *Service) keyGrants(ctx context.Context, region, keyID string) ([]grant, error) {
	gs, err := s.grants(region).List(ctx, func(g grant) bool { return g.KeyID == keyID })
	slices.SortStableFunc(gs, func(a, b grant) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return gs, err
}

type grantView struct {
	KeyID                string   `json:"key_id"`
	GrantID              string   `json:"grant_id"`
	GranteePrincipal     string   `json:"grantee_principal"`
	GranteePrincipalType string   `json:"grantee_principal_type"`
	Operations           []string `json:"operations"`
	IssuingPrincipal     string   `json:"issuing_principal"`
	CreationDate         string   `json:"creation_date"`
	Name                 string   `json:"name"`
	RetiringPrincipal    string   `json:"retiring_principal"`
}

func viewGrant(g grant) grantView {
	return grantView{
		KeyID: g.KeyID, GrantID: g.ID, GranteePrincipal: g.Grantee, GranteePrincipalType: g.GranteeType,
		Operations: g.Operations, IssuingPrincipal: g.Issuer, CreationDate: millis(g.CreatedAt), Name: g.Name,
		RetiringPrincipal: g.Retiring,
	}
}

func (s *Service) handleCreateGrant(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b struct {
		KeyID                string   `json:"key_id"`
		GranteePrincipal     string   `json:"grantee_principal"`
		Operations           []string `json:"operations"`
		Name                 string   `json:"name"`
		RetiringPrincipal    string   `json:"retiring_principal"`
		GranteePrincipalType string   `json:"grantee_principal_type"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	k, err := s.authorized(r, t, "kms:cmk:createGrant", b.KeyID)
	if err != nil {
		return err
	}
	if b.GranteePrincipalType == "" {
		b.GranteePrincipalType = granteeUser
	}
	switch {
	case b.GranteePrincipal == "" || len(b.Operations) == 0:
		return errMissing
	case !validPrincipal(b.GranteePrincipal):
		return errGrantee
	case b.GranteePrincipalType != granteeUser && b.GranteePrincipalType != granteeDomain:
		return errParam
	case b.RetiringPrincipal != "" && !validPrincipal(b.RetiringPrincipal):
		return errGrantee
	case b.Name != "" && (len(b.Name) > maxAlias || !aliasRE.MatchString(b.Name)):
		return errParam
	case k.Default:
		return errDefaultKey
	case k.State == statePendingDeletion:
		return errPendingDeletion
	}
	ops := []string{}
	for _, op := range b.Operations {
		if !validOperation(op) {
			return errParam
		}
		if !slices.Contains(ops, op) {
			ops = append(ops, op)
		}
	}
	if len(ops) == 1 && ops[0] == "create-grant" {
		return errGrantOps
	}
	userID, accountID := s.caller(r.Context())
	issuer := userID
	if issuer == "" {
		issuer = accountID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.keyGrants(r.Context(), t.Region, k.ID)
	if err != nil {
		return err
	}
	if len(existing) >= maxGrantsPerKey {
		return errKeyGrants
	}
	g := grant{
		ID: s.ids.Hex32() + s.ids.Hex32(), KeyID: k.ID, Grantee: b.GranteePrincipal, GranteeType: b.GranteePrincipalType,
		Operations: ops, Name: b.Name, Retiring: b.RetiringPrincipal, Issuer: issuer,
		CreatedAt: s.now().UTC().Truncate(time.Millisecond),
	}
	if err := s.grants(t.Region).Create(r.Context(), g.ID, g); err != nil {
		return err
	}
	s.log.InfoContext(r.Context(), "kms grant created", "key_id", k.ID, "grant_id", g.ID, "grantee", g.Grantee, "type", g.GranteeType)
	return write(w, struct {
		GrantID string `json:"grant_id"`
	}{g.ID})
}

// grantPage pages grants as list-grants does.
func grantPage(gs []grant, limit, marker number) (any, error) {
	n, off := maxGrantsPerKey, 0
	if limit.set {
		if limit.bad || limit.v < 1 || limit.v > maxGrantsPerKey {
			return nil, errLimit
		}
		n = limit.v
	}
	if marker.set {
		if marker.bad || marker.v < 0 {
			return nil, errMarker
		}
		off = marker.v
	}
	out := struct {
		Grants     []grantView `json:"grants"`
		NextMarker string      `json:"next_marker"`
		Truncated  string      `json:"truncated"`
		Total      int         `json:"total"`
	}{Grants: []grantView{}, Truncated: "false", Total: len(gs)}
	if off < len(gs) {
		for _, g := range gs[off:min(off+n, len(gs))] {
			out.Grants = append(out.Grants, viewGrant(g))
		}
		if off+n < len(gs) {
			out.Truncated, out.NextMarker = "true", strconv.Itoa(off+n)
		}
	}
	return out, nil
}

func (s *Service) handleListGrants(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b struct {
		KeyID  string `json:"key_id"`
		Limit  number `json:"limit"`
		Marker number `json:"marker"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	k, err := s.authorized(r, t, "kms:cmk:listGrants", b.KeyID)
	if err != nil {
		return err
	}
	gs, err := s.keyGrants(r.Context(), t.Region, k.ID)
	if err != nil {
		return err
	}
	out, err := grantPage(gs, b.Limit, b.Marker)
	if err != nil {
		return err
	}
	return write(w, out)
}

func (s *Service) handleListRetirableGrants(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b struct {
		Limit  number `json:"limit"`
		Marker number `json:"marker"`
	}
	if err := decode(r, &b); err != nil {
		return err
	}
	userID, _ := s.caller(r.Context())
	gs, err := s.grants(t.Region).List(r.Context(), func(g grant) bool { return userID != "" && g.Retiring == userID })
	if err != nil {
		return err
	}
	slices.SortStableFunc(gs, func(a, b grant) int { return a.CreatedAt.Compare(b.CreatedAt) })
	out, err := grantPage(gs, b.Limit, b.Marker)
	if err != nil {
		return err
	}
	return write(w, out)
}

type grantRef struct {
	KeyID   string `json:"key_id"`
	GrantID string `json:"grant_id"`
}

// keyGrant finds a grant of a key.
func (s *Service) keyGrant(ctx context.Context, region string, b grantRef) (grant, error) {
	if b.GrantID == "" {
		return grant{}, errMissing
	}
	if !grantIDRE.MatchString(b.GrantID) {
		return grant{}, errGrantID
	}
	g, err := s.grants(region).Get(ctx, b.GrantID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return grant{}, errGrantID
	case err != nil:
		return grant{}, err
	case g.KeyID != b.KeyID:
		return grant{}, errGrantMismatch
	}
	return g, nil
}

func (s *Service) handleRevokeGrant(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b grantRef
	if err := decode(r, &b); err != nil {
		return err
	}
	k, err := s.authorized(r, t, "kms:cmk:revokeGrant", b.KeyID)
	if err != nil {
		return err
	}
	if _, err := s.keyGrant(r.Context(), t.Region, grantRef{KeyID: k.ID, GrantID: b.GrantID}); err != nil {
		return err
	}
	if err := s.grants(t.Region).Delete(r.Context(), b.GrantID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return emptyObject(w)
}

func (s *Service) handleRetireGrant(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b grantRef
	if err := decode(r, &b); err != nil {
		return err
	}
	if b.KeyID == "" {
		return errMissing
	}
	if !keyIDRE.MatchString(b.KeyID) {
		return errKeyID
	}
	// The retiring principal retires the grant whatever its policies.
	userID, _ := s.caller(r.Context())
	g, err := s.keyGrant(r.Context(), t.Region, b)
	if err == nil && userID != "" && g.Retiring == userID {
		authz.Granted(r)
	} else if _, err := s.authorized(r, t, "kms:cmk:retireGrant", b.KeyID); err != nil {
		return err
	} else if g, err = s.keyGrant(r.Context(), t.Region, b); err != nil {
		return err
	}
	if err := s.grants(t.Region).Delete(r.Context(), g.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return emptyObject(w)
}
