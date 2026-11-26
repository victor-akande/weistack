package csms

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/authz"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	charsLowercase   = "abcdefghijklmnopqrstuvwxyz"
	charsUppercase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsDigits      = "0123456789"
	charsPunctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	charsSpace       = " "
)

type scheduleDeleteRequest struct {
	RecoveryWindowInDays *int `json:"recovery_window_in_days"`
}

type uploadSecretBlobRequest struct {
	SecretBlob string `json:"secret_blob"`
}

type downloadSecretBlobResponse struct {
	SecretBlob string `json:"secret_blob"`
}

type generatePasswordRequest struct {
	PasswordPolicyName      *string `json:"password_policy_name"`
	Length                  *int    `json:"length"`
	ExcludeCharacters       *string `json:"exclude_characters"`
	ExcludeLowercase        *bool   `json:"exclude_lowercase"`
	ExcludeUppercase        *bool   `json:"exclude_uppercase"`
	ExcludeNumbers          *bool   `json:"exclude_numbers"`
	ExcludePunctuation      *bool   `json:"exclude_punctuation"`
	IncludeSpace            *bool   `json:"include_space"`
	RequireEachIncludedType *bool   `json:"require_each_included_type"`
}

type generatePasswordResponse struct {
	Password string `json:"password"`
}

type backupPayload struct {
	AccountID string    `json:"account_id"`
	Region    string    `json:"region"`
	Secret    Secret    `json:"secret"`
	Versions  []Version `json:"versions"`
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	if err := httpx.DecodeJSON(r, dst); err != nil {
		if errors.Is(err, httpx.ErrEmptyBody) {
			return nil
		}
		return errBodyFormat
	}
	return nil
}

// Resume re-schedules any pending secret deletions after a restart.
func (s *Service) Resume(ctx context.Context) error {
	dump, err := s.store.Dump(ctx)
	if err != nil {
		return fmt.Errorf("csms: resuming scheduled deletions: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, recs := range dump {
		scope, err := store.ParseScope(key)
		if err != nil || scope.Kind != kindSecret {
			continue
		}
		t := Tenant{Region: scope.Region, ProjectID: scope.ProjectID}
		for _, rec := range recs {
			var sec Secret
			if err := json.Unmarshal(rec.Data, &sec); err != nil {
				return fmt.Errorf("csms: decoding %s/%s: %w", key, rec.ID, err)
			}
			if sec.State != statePendingDelete || sec.ScheduledDeleteAt <= 0 {
				continue
			}
			s.engine.Cancel(sec.ID)
			s.scheduleDeleteTask(t, sec.ID, sec.Name, time.UnixMilli(sec.ScheduledDeleteAt).UTC())
		}
	}
	return nil
}

func (s *Service) scheduleDeleteTask(t Tenant, secID, secName string, deleteAt time.Time) {
	delay := deleteAt.Sub(s.clock().UTC())
	s.engine.ScheduleAfter(delay, lifecycle.Task{
		Key:  secID,
		Kind: kindDeleteTransition,
		Run: func(ctx context.Context, fault error) {
			s.runDeleteSecret(ctx, t, secID, secName, fault)
		},
	})
}

func (s *Service) runDeleteSecret(ctx context.Context, t Tenant, secID, secName string, fault error) {
	if fault != nil {
		s.log.WarnContext(ctx, "csms scheduled secret deletion faulted",
			"secret_id", secID,
			"secret_name", secName,
		)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sec, err := s.secrets(t).Get(ctx, secName)
	if errors.Is(err, store.ErrNotFound) {
		return
	}
	if err != nil {
		s.log.ErrorContext(ctx, "csms loading secret for scheduled deletion failed",
			"secret_id", secID,
			"secret_name", secName,
		)
		return
	}
	if sec.ID != secID || sec.State != statePendingDelete {
		return
	}

	if err := s.deleteSecretVersionsLocked(ctx, t, sec.Name); err != nil {
		s.log.ErrorContext(ctx, "csms deleting secret versions failed",
			"secret_id", secID,
			"secret_name", secName,
		)
		return
	}
	if err := s.secrets(t).Delete(ctx, sec.Name); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "csms deleting scheduled secret failed",
			"secret_id", secID,
			"secret_name", secName,
		)
	}
}

func (s *Service) deleteSecretVersionsLocked(ctx context.Context, t Tenant, secretName string) error {
	prefix := secretName + "/"
	verScope := store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVersion}
	recs, err := s.store.List(ctx, verScope)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if !strings.HasPrefix(rec.ID, prefix) {
			continue
		}
		if err := s.store.Delete(ctx, verScope, rec.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (s *Service) listSecretVersionsSorted(ctx context.Context, t Tenant, secretName string) ([]Version, error) {
	prefix := secretName + "/"
	verScope := store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVersion}
	recs, err := s.store.List(ctx, verScope)
	if err != nil {
		return nil, err
	}
	vers := make([]Version, 0)
	for _, rec := range recs {
		if !strings.HasPrefix(rec.ID, prefix) {
			continue
		}
		var ver Version
		if err := json.Unmarshal(rec.Data, &ver); err != nil {
			return nil, err
		}
		vers = append(vers, ver)
	}
	sort.Slice(vers, func(i, j int) bool {
		return parseVersionNum(vers[i].ID) < parseVersionNum(vers[j].ID)
	})
	return vers, nil
}

func (s *Service) handleDeleteSecretForSchedule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	secretName := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(secretName) {
		return errParam
	}

	var req scheduleDeleteRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		return err
	}
	days := defaultRecoveryDays
	if req.RecoveryWindowInDays != nil {
		days = *req.RecoveryWindowInDays
		if days < minRecoveryDays || days > maxRecoveryDays {
			return errParam
		}
	}

	ctx := r.Context()
	s.mu.Lock()
	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if sec.State == statePendingDelete {
		s.mu.Unlock()
		return errAlreadyScheduled
	}

	now := s.clock().UTC()
	deleteAt := now.Add(time.Duration(days) * 24 * time.Hour)
	sec.State = statePendingDelete
	sec.ScheduledDeleteAt = deleteAt.UnixMilli()
	sec.UpdatedAt = now.UnixMilli()
	if err := s.secrets(t).Put(ctx, sec.Name, sec); err != nil {
		s.mu.Unlock()
		return err
	}
	s.engine.Cancel(sec.ID)
	s.scheduleDeleteTask(t, sec.ID, sec.Name, deleteAt)
	s.mu.Unlock()

	return httpx.WriteJSON(w, http.StatusOK, secretResponse{
		Secret: toSecretView(sec, s.accountID(ctx)),
	})
}

func (s *Service) handleRestoreSecret(w http.ResponseWriter, r *http.Request, t Tenant) error {
	secretName := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(secretName) {
		return errParam
	}

	ctx := r.Context()
	s.mu.Lock()
	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if sec.State != statePendingDelete {
		s.mu.Unlock()
		return errNotScheduled
	}

	s.engine.Cancel(sec.ID)
	sec.State = stateEnabled
	sec.ScheduledDeleteAt = 0
	sec.UpdatedAt = s.nowMillis()
	if err := s.secrets(t).Put(ctx, sec.Name, sec); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	return httpx.WriteJSON(w, http.StatusOK, secretResponse{
		Secret: toSecretView(sec, s.accountID(ctx)),
	})
}

func collectKMSKeyIDs(sec Secret, vers []Version) []string {
	seen := make(map[string]struct{}, 1+len(vers))
	out := make([]string, 0, 1+len(vers))
	add := func(id string) {
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	add(sec.KMSKeyID)
	for _, ver := range vers {
		add(ver.KMSKeyID)
	}
	return out
}

func (s *Service) openBackupBlob(blob string) (backupPayload, error) {
	if !strings.HasPrefix(blob, backupPrefix) {
		return backupPayload{}, errParam
	}
	encoded := strings.TrimPrefix(blob, backupPrefix)
	if encoded == "" {
		return backupPayload{}, errParam
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return backupPayload{}, errParam
	}
	rawJSON, err := s.vault.Open(sealed, backupVaultLabel)
	if err != nil {
		return backupPayload{}, errParam
	}
	var p backupPayload
	if err := json.Unmarshal([]byte(rawJSON), &p); err != nil {
		return backupPayload{}, errParam
	}
	if !nameRE.MatchString(p.Secret.Name) {
		return backupPayload{}, errParam
	}
	return p, nil
}

func (s *Service) peekBackupSecretName(blob string) string {
	p, err := s.openBackupBlob(blob)
	if err != nil {
		return ""
	}
	return p.Secret.Name
}

func (s *Service) handleDownloadSecretBlob(w http.ResponseWriter, r *http.Request, t Tenant) error {
	secretName := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(secretName) {
		return errParam
	}

	ctx := r.Context()
	s.mu.Lock()
	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return errNotFound
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if sec.State != stateEnabled {
		s.mu.Unlock()
		return errStateNotEnabled
	}
	vers, err := s.listSecretVersionsSorted(ctx, t, sec.Name)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	acctID := s.accountID(ctx)
	for _, keyID := range collectKMSKeyIDs(sec, vers) {
		keyRes := authz.Resource{URN: "kms:" + t.Region + ":" + acctID + ":KeyId:" + keyID}
		if err := authz.CheckDependency(r, "kms", "kms:cmk:createDataKey", keyRes); err != nil {
			return err
		}
		if err := authz.CheckDependency(r, "kms", "kms:cmk:decryptDataKey", keyRes); err != nil {
			return err
		}
	}

	payloadJSON, err := json.Marshal(backupPayload{
		AccountID: acctID,
		Region:    t.Region,
		Secret:    sec,
		Versions:  vers,
	})
	if err != nil {
		return err
	}
	sealed, err := s.vault.Seal(string(payloadJSON), backupVaultLabel)
	if err != nil {
		return err
	}
	blob := backupPrefix + base64.RawURLEncoding.EncodeToString(sealed)

	return httpx.WriteJSON(w, http.StatusOK, downloadSecretBlobResponse{
		SecretBlob: blob,
	})
}

func (s *Service) handleUploadSecretBlob(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req uploadSecretBlobRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.SecretBlob == "" {
		return errParam
	}

	p, err := s.openBackupBlob(req.SecretBlob)
	if err != nil {
		return err
	}

	ctx := r.Context()
	acctID := s.accountID(ctx)
	if p.AccountID != acctID || p.Region != t.Region {
		return errParam
	}

	for _, keyID := range collectKMSKeyIDs(p.Secret, p.Versions) {
		keyRes := authz.Resource{URN: "kms:" + t.Region + ":" + acctID + ":KeyId:" + keyID}
		if err := authz.CheckDependency(r, "kms", "kms:cmk:decryptDataKey", keyRes); err != nil {
			return err
		}
	}

	s.mu.Lock()
	_, getErr := s.secrets(t).Get(ctx, p.Secret.Name)
	if getErr == nil {
		s.mu.Unlock()
		return errSecretExists
	}
	if !errors.Is(getErr, store.ErrNotFound) {
		s.mu.Unlock()
		return getErr
	}

	existing, err := s.secrets(t).List(ctx, nil)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if !s.quotas.Allows(quota.CSMSSecret, len(existing), 1) {
		s.mu.Unlock()
		return errSecretQuota
	}

	restored := p.Secret
	restored.State = stateEnabled
	restored.ScheduledDeleteAt = 0
	restored.UpdatedAt = s.nowMillis()
	if restored.Stages == nil {
		restored.Stages = make(map[string]Stage)
	}
	if restored.Tags == nil {
		restored.Tags = []Tag{}
	}

	if err := s.deleteSecretVersionsLocked(ctx, t, restored.Name); err != nil {
		s.mu.Unlock()
		return err
	}
	for _, ver := range p.Versions {
		if err := s.versions(t).Put(ctx, versionStoreKey(restored.Name, ver.ID), ver); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	if err := s.secrets(t).Put(ctx, restored.Name, restored); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	return httpx.WriteJSON(w, http.StatusOK, secretResponse{
		Secret: toSecretView(restored, acctID),
	})
}

func (s *Service) handleGenerateRandomPassword(w http.ResponseWriter, r *http.Request, _ Tenant) error {
	var req generatePasswordRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		return err
	}
	if req.PasswordPolicyName != nil && *req.PasswordPolicyName != "" {
		return errParam
	}

	length := defaultPasswordLen
	if req.Length != nil {
		length = *req.Length
		if length < minPasswordLen || length > maxPasswordLen {
			return errParam
		}
	}

	excluded := make(map[byte]bool)
	if req.ExcludeCharacters != nil {
		excl := *req.ExcludeCharacters
		for i := range len(excl) {
			b := excl[i]
			if b < 33 || b > 126 {
				return errParam
			}
			excluded[b] = true
		}
	}

	exclLower := boolVal(req.ExcludeLowercase)
	exclUpper := boolVal(req.ExcludeUppercase)
	exclNum := boolVal(req.ExcludeNumbers)
	exclPunct := boolVal(req.ExcludePunctuation)
	inclSpace := boolVal(req.IncludeSpace)
	requireEach := boolVal(req.RequireEachIncludedType)

	if requireEach && (exclLower || exclUpper || exclNum || exclPunct || length < 4) {
		return errParam
	}

	var activeClasses []string
	addClass := func(chars string) bool {
		filtered := filterExcludedChars(chars, excluded)
		if filtered == "" {
			return false
		}
		activeClasses = append(activeClasses, filtered)
		return true
	}

	if !exclLower && !addClass(charsLowercase) && requireEach {
		return errParam
	}
	if !exclUpper && !addClass(charsUppercase) && requireEach {
		return errParam
	}
	if !exclNum && !addClass(charsDigits) && requireEach {
		return errParam
	}
	if !exclPunct && !addClass(charsPunctuation) && requireEach {
		return errParam
	}
	if inclSpace {
		addClass(charsSpace)
	}

	if len(activeClasses) == 0 {
		return errParam
	}
	if requireEach && length < len(activeClasses) {
		return errParam
	}

	pw, err := generatePassword(length, activeClasses)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, generatePasswordResponse{
		Password: pw,
	})
}

func boolVal(p *bool) bool {
	return p != nil && *p
}

func filterExcludedChars(chars string, excluded map[byte]bool) string {
	if len(excluded) == 0 {
		return chars
	}
	var b strings.Builder
	b.Grow(len(chars))
	for i := range len(chars) {
		if !excluded[chars[i]] {
			b.WriteByte(chars[i])
		}
	}
	return b.String()
}

func generatePassword(length int, activeClasses []string) (string, error) {
	if length < minPasswordLen || length > maxPasswordLen {
		return "", errParam
	}
	pool := strings.Join(activeClasses, "")
	out := make([]byte, 0, length)

	if length >= len(activeClasses) {
		for _, cls := range activeClasses {
			ch, err := randByteFrom(cls)
			if err != nil {
				return "", err
			}
			out = append(out, ch)
		}
	}
	for len(out) < length {
		ch, err := randByteFrom(pool)
		if err != nil {
			return "", err
		}
		out = append(out, ch)
	}

	for i := len(out) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := n.Int64()
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

func randByteFrom(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}
