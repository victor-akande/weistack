package iam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/identity"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Permanent access keys, through classic IAM's /v3.0/OS-CREDENTIAL and
// IAM 5.0's /v5/users/{user_id}/access-keys, over one record per key.
//
// Active keys are registered with the identity directory, so requests
// signed with them act as their user. The bootstrap administrator's key is
// not an IAM record and is never listed.

const kindAccessKey = "iam.accesskey"

// maxKeysPerUser is IAM's quota of permanent access keys per user, the
// same in both generations (productdesc-iam/iam_01_0305).
const maxKeysPerUser = 2

const (
	keyActive   = "active"
	keyInactive = "inactive"
)

// accessKey is a permanent access key. Its ID is the AK.
type accessKey struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// Secret is the SK, sealed by the vault with the AK as its label.
	Secret      []byte    `json:"secret"`
	Status      string    `json:"status"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	// LastUsedAt is when the key was last used before it was last
	// deactivated. Later uses are in the directory's memory.
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
}

func (s *Service) accessKeys() store.Collection[accessKey] {
	return store.Of[accessKey](s.store, global(kindAccessKey))
}

func (s *Service) keysOf(ctx context.Context, userID string) ([]accessKey, error) {
	return s.accessKeys().List(ctx, func(k accessKey) bool { return k.UserID == userID })
}

// lastUsed is when k was last used, if ever.
func (s *Service) lastUsed(k accessKey) (time.Time, bool) {
	t, ok := s.dir.LastUsed(k.ID)
	if !ok || t.Before(k.LastUsedAt) {
		return k.LastUsedAt, !k.LastUsedAt.IsZero()
	}
	return t, true
}

// register makes an active key known as its user's, with its secret so
// that signatures can be checked, and forgets an inactive one. A disabled
// user's keys stay known, marked disabled.
func (s *Service) register(k accessKey, u user) error {
	if k.Status != keyActive {
		s.dir.Forget(k.ID)
		return nil
	}
	secret, err := s.vault.Open(k.Secret, k.ID)
	if err != nil {
		return fmt.Errorf("iam: opening the secret of %s: %w", k.ID, err)
	}
	p := identity.Principal{AccountID: s.account().ID, UserID: u.ID, UserName: u.Name, Disabled: !u.Enabled}
	return s.dir.Register(k.ID, p, secret)
}

// registerKeysOf registers u's keys again, after a rename.
func (s *Service) registerKeysOf(ctx context.Context, u user) error {
	keys, err := s.keysOf(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.register(k, u); err != nil {
			return err
		}
	}
	return nil
}

// registerAllKeys registers every stored key, at start.
func (s *Service) registerAllKeys(ctx context.Context) error {
	users, err := s.users().List(ctx, nil)
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := s.registerKeysOf(ctx, u); err != nil {
			return err
		}
	}
	return nil
}

// deleteKeysOf removes a user's keys. The caller holds s.mu.
func (s *Service) deleteKeysOf(ctx context.Context, userID string) error {
	keys, err := s.keysOf(ctx, userID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		s.dir.Forget(k.ID)
		if err := s.accessKeys().Delete(ctx, k.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

// errQuota is returned by createKey when the user has all their keys.
var errQuota = errors.New("access key quota reached")

// createKey makes a key for u. It returns the key and its secret.
func (s *Service) createKey(ctx context.Context, u user, description string) (accessKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, err := s.keysOf(ctx, u.ID)
	if err != nil {
		return accessKey{}, "", err
	}
	if len(keys) >= maxKeysPerUser {
		return accessKey{}, "", errQuota
	}
	for {
		creds, err := identity.NewCredentials()
		if err != nil {
			return accessKey{}, "", err
		}
		if _, known := s.dir.Lookup(creds.AccessKey); known {
			continue // an AK the directory already holds
		}
		sealed, err := s.vault.Seal(creds.SecretKey, creds.AccessKey)
		if err != nil {
			return accessKey{}, "", err
		}
		k := accessKey{
			ID: creds.AccessKey, UserID: u.ID, Secret: sealed, Status: keyActive,
			Description: description, CreatedAt: s.now().UTC(),
		}
		err = s.accessKeys().Create(ctx, k.ID, k)
		if errors.Is(err, store.ErrExists) {
			continue
		}
		if err != nil {
			return accessKey{}, "", err
		}
		return k, creds.SecretKey, s.register(k, u)
	}
}

// updateKey sets a key's status or description; nil leaves them.
func (s *Service) updateKey(ctx context.Context, k accessKey, status, description *string) (accessKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.users().Get(ctx, k.UserID)
	if err != nil {
		return accessKey{}, err
	}
	k, err = s.accessKeys().Update(ctx, k.ID, func(k *accessKey) error {
		if status != nil && *status != k.Status {
			if *status == keyInactive {
				if t, ok := s.lastUsed(*k); ok {
					k.LastUsedAt = t
				}
			}
			k.Status = *status
		}
		if description != nil {
			k.Description = *description
		}
		return nil
	})
	if err != nil {
		return accessKey{}, err
	}
	return k, s.register(k, u)
}

func (s *Service) deleteKey(ctx context.Context, ak string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir.Forget(ak)
	return s.accessKeys().Delete(ctx, ak)
}

func validKeyStatus(s *string) bool { return s == nil || *s == keyActive || *s == keyInactive }

// Classic IAM: /v3.0/OS-CREDENTIAL/credentials.

// credentialTime is the documented format of classic key times, as in
// "2023-06-28T08:56:33.710000Z".
const credentialTime = "2006-01-02T15:04:05.000000Z"

// credentialView mirrors the SDK models CreateCredentialResult,
// ShowCredential, Credentials and UpdateCredentialResult.
type credentialView struct {
	UserID      string `json:"user_id"`
	Access      string `json:"access"`
	Secret      string `json:"secret,omitempty"`
	Status      string `json:"status"`
	CreateTime  string `json:"create_time"`
	LastUseTime string `json:"last_use_time,omitempty"`
	Description string `json:"description"`
}

func credential(k accessKey) credentialView {
	return credentialView{
		UserID: k.UserID, Access: k.ID, Status: k.Status,
		CreateTime: k.CreatedAt.UTC().Format(credentialTime), Description: k.Description,
	}
}

type credentialResponse struct {
	Credential credentialView `json:"credential"`
}

// writeKeyQuota writes the documented response to a create past the
// quota, which is Keystone's envelope, not the flat one.
func writeKeyQuota(w http.ResponseWriter) error {
	type keystoneError struct {
		Message   string  `json:"message"`
		Code      int     `json:"code"`
		Title     string  `json:"title"`
		ErrorMsg  *string `json:"error_msg"`
		ErrorCode *string `json:"error_code"`
	}
	return httpx.WriteJSON(w, http.StatusBadRequest, struct {
		Error keystoneError `json:"error"`
	}{keystoneError{Message: "akSkNumExceed", Code: http.StatusBadRequest, Title: "Bad Request"}})
}

// POST /v3.0/OS-CREDENTIAL/credentials.
func (s *Service) handleCreateCredential(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Credential *struct {
			UserID      *string `json:"user_id"`
			Description *string `json:"description"`
		} `json:"credential"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	switch {
	case b.Credential == nil:
		return errRequired("credential")
	case b.Credential.UserID == nil || *b.Credential.UserID == "":
		return errRequired("user_id")
	}
	u, err := s.users().Get(r.Context(), *b.Credential.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("user", *b.Credential.UserID)
	}
	if err != nil {
		return err
	}
	k, secret, err := s.createKey(r.Context(), u, deref(b.Credential.Description))
	if errors.Is(err, errQuota) {
		return writeKeyQuota(w)
	}
	if err != nil {
		return err
	}
	v := credential(k)
	v.Secret = secret
	return httpx.WriteJSON(w, http.StatusCreated, credentialResponse{v})
}

// caller returns the ID of the user a request acts as: the user whose key
// signed it, or, for any other key, the root user.
func (s *Service) caller(r *http.Request) string {
	if id := auth.FromContext(r.Context()); id.Known && id.Principal.UserID != "" {
		return id.Principal.UserID
	}
	return s.account().RootUserID()
}

// GET /v3.0/OS-CREDENTIAL/credentials: a user's keys, the caller's by
// default.
func (s *Service) handleListCredentials(w http.ResponseWriter, r *http.Request) error {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = s.caller(r)
	}
	if _, err := s.users().Get(r.Context(), userID); errors.Is(err, store.ErrNotFound) {
		return errNotFound("user", userID)
	} else if err != nil {
		return err
	}
	keys, err := s.keysOf(r.Context(), userID)
	if err != nil {
		return err
	}
	out := struct {
		Credentials []credentialView `json:"credentials"`
	}{make([]credentialView, 0, len(keys))}
	for _, k := range keys {
		out.Credentials = append(out.Credentials, credential(k))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) getCredential(r *http.Request) (accessKey, error) {
	ak := chi.URLParam(r, "access_key")
	k, err := s.accessKeys().Get(r.Context(), ak)
	if errors.Is(err, store.ErrNotFound) {
		return accessKey{}, errNotFound("credential", ak)
	}
	return k, err
}

// GET /v3.0/OS-CREDENTIAL/credentials/{access_key}. A key never used
// shows its creation time as its last use, as documented.
func (s *Service) handleShowCredential(w http.ResponseWriter, r *http.Request) error {
	k, err := s.getCredential(r)
	if err != nil {
		return err
	}
	v := credential(k)
	v.LastUseTime = v.CreateTime
	if t, ok := s.lastUsed(k); ok {
		v.LastUseTime = t.UTC().Format(credentialTime)
	}
	return httpx.WriteJSON(w, http.StatusOK, credentialResponse{v})
}

// PUT /v3.0/OS-CREDENTIAL/credentials/{access_key}.
func (s *Service) handleUpdateCredential(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Credential *struct {
			Status      *string `json:"status"`
			Description *string `json:"description"`
		} `json:"credential"`
	}
	if err := decodeClassic(r, &b); err != nil {
		return err
	}
	if b.Credential == nil {
		return errRequired("credential")
	}
	if !validKeyStatus(b.Credential.Status) {
		return errInvalidField("status", *b.Credential.Status)
	}
	k, err := s.getCredential(r)
	if err != nil {
		return err
	}
	ak := k.ID
	k, err = s.updateKey(r.Context(), k, b.Credential.Status, b.Credential.Description)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("credential", ak)
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, credentialResponse{credential(k)})
}

// DELETE /v3.0/OS-CREDENTIAL/credentials/{access_key}.
func (s *Service) handleDeleteCredential(w http.ResponseWriter, r *http.Request) error {
	k, err := s.getCredential(r)
	if err != nil {
		return err
	}
	if err := s.deleteKey(r.Context(), k.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// IAM 5.0: /v5/users/{user_id}/access-keys.

// v5AccessKeyView mirrors the SDK models AccessKey and AccessKeyMetadata.
type v5AccessKeyView struct {
	UserID          string `json:"user_id"`
	AccessKeyID     string `json:"access_key_id"`
	CreatedAt       string `json:"created_at"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	Status          string `json:"status"`
}

func v5AccessKey(k accessKey) v5AccessKeyView {
	return v5AccessKeyView{UserID: k.UserID, AccessKeyID: k.ID, CreatedAt: v5At(k.CreatedAt), Status: k.Status}
}

type v5AccessKeyResponse struct {
	AccessKey v5AccessKeyView `json:"access_key"`
}

// errV5NoKey answers for an access key the user does not have. IAM 5.0
// documents a 404 but no code for it, so this is classic IAM's.
func errV5NoKey(ak string) *apierr.Error { return errNotFound("access key", ak) }

// v5Key returns the key in the path, which must be the user's.
func (s *Service) v5Key(r *http.Request) (accessKey, error) {
	u, err := s.getUserV5(r)
	if err != nil {
		return accessKey{}, err
	}
	ak := chi.URLParam(r, "access_key_id")
	k, err := s.accessKeys().Get(r.Context(), ak)
	if errors.Is(err, store.ErrNotFound) || (err == nil && k.UserID != u.ID) {
		return accessKey{}, errV5NoKey(ak)
	}
	return k, err
}

// POST /v5/users/{user_id}/access-keys. Past the quota it answers
// PAP5.0257: IAM 5.0 documents a 400 but no code for it.
func (s *Service) handleCreateAccessKeyV5(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUserV5(r)
	if err != nil {
		return err
	}
	k, secret, err := s.createKey(r.Context(), u, "")
	if errors.Is(err, errQuota) {
		return errV5Input.WithCause(err)
	}
	if err != nil {
		return err
	}
	v := v5AccessKey(k)
	v.SecretAccessKey = secret
	return httpx.WriteJSON(w, http.StatusCreated, v5AccessKeyResponse{v})
}

// GET /v5/users/{user_id}/access-keys.
func (s *Service) handleListAccessKeysV5(w http.ResponseWriter, r *http.Request) error {
	u, err := s.getUserV5(r)
	if err != nil {
		return err
	}
	all, err := s.keysOf(r.Context(), u.ID)
	if err != nil {
		return err
	}
	got, info, err := page(r, all, func(k accessKey) string { return k.ID })
	if err != nil {
		return err
	}
	out := struct {
		AccessKeys []v5AccessKeyView `json:"access_keys"`
		PageInfo   pageInfo          `json:"page_info"`
	}{make([]v5AccessKeyView, 0, len(got)), info}
	for _, k := range got {
		out.AccessKeys = append(out.AccessKeys, v5AccessKey(k))
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}

// PUT /v5/users/{user_id}/access-keys/{access_key_id}: the status.
func (s *Service) handleUpdateAccessKeyV5(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Status *string `json:"status"`
	}
	if err := decodeV5(r, &b); err != nil {
		return err
	}
	if b.Status == nil || !validKeyStatus(b.Status) {
		return errV5Input
	}
	k, err := s.v5Key(r)
	if err != nil {
		return err
	}
	ak := k.ID
	k, err = s.updateKey(r.Context(), k, b.Status, nil)
	if errors.Is(err, store.ErrNotFound) {
		return errV5NoKey(ak)
	}
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, v5AccessKeyResponse{v5AccessKey(k)})
}

// DELETE /v5/users/{user_id}/access-keys/{access_key_id}.
func (s *Service) handleDeleteAccessKeyV5(w http.ResponseWriter, r *http.Request) error {
	k, err := s.v5Key(r)
	if err != nil {
		return err
	}
	if err := s.deleteKey(r.Context(), k.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// GET /v5/users/{user_id}/access-keys/{access_key_id}/last-used. A key
// never used has no last_used_at.
func (s *Service) handleShowAccessKeyLastUsedV5(w http.ResponseWriter, r *http.Request) error {
	k, err := s.v5Key(r)
	if err != nil {
		return err
	}
	var v struct {
		LastUsedAt string `json:"last_used_at,omitempty"`
	}
	if t, ok := s.lastUsed(k); ok {
		v.LastUsedAt = v5At(t)
	}
	return httpx.WriteJSON(w, http.StatusOK, struct {
		AccessKeyLastUsed any `json:"access_key_last_used"`
	}{v})
}
