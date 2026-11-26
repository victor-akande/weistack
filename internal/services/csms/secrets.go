package csms

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
	"github.com/victor-akande/weistack/internal/core/store"
)

type createSecretRequestBody struct {
	Name                string    `json:"name"`
	KMSKeyID            *string   `json:"kms_key_id"`
	Description         *string   `json:"description"`
	SecretBinary        *string   `json:"secret_binary"`
	SecretString        *string   `json:"secret_string"`
	SecretType          *string   `json:"secret_type"`
	AutoRotation        *bool     `json:"auto_rotation"`
	RotationPeriod      *string   `json:"rotation_period"`
	RotationConfig      *string   `json:"rotation_config"`
	EventSubscriptions  *[]string `json:"event_subscriptions"`
	EnterpriseProjectID *string   `json:"enterprise_project_id"`
	RotationFuncURN     *string   `json:"rotation_func_urn"`
}

type updateSecretRequestBody struct {
	KMSKeyID           *string   `json:"kms_key_id"`
	Description        *string   `json:"description"`
	AutoRotation       *bool     `json:"auto_rotation"`
	RotationPeriod     *string   `json:"rotation_period"`
	EventSubscriptions *[]string `json:"event_subscriptions"`
	RotationFuncURN    *string   `json:"rotation_func_urn"`
}

func parseEventSubscriptions(in *[]string) ([]string, error) {
	if in == nil {
		return []string{}, nil
	}
	subs := make([]string, 0, len(*in))
	for _, item := range *in {
		if item == "" {
			continue
		}
		if !nameRE.MatchString(item) {
			return nil, errParam
		}
		subs = append(subs, item)
	}
	if len(subs) > maxEventSubs {
		return nil, errParam
	}
	return subs, nil
}

func (s *Service) handleCreateSecret(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	var b createSecretRequestBody
	if err := decodeJSON(r, &b); err != nil {
		return err
	}
	if !nameRE.MatchString(b.Name) {
		return errParam
	}

	if b.SecretType != nil && *b.SecretType != "" && *b.SecretType != secretTypeCommon {
		switch *b.SecretType {
		case "RDS", "RDS-FG", "GaussDB-FG":
			return errNotImplemented("secret_type " + *b.SecretType)
		default:
			return errParam
		}
	}
	if b.AutoRotation != nil && *b.AutoRotation {
		return errNotImplemented("auto_rotation")
	}
	if b.RotationPeriod != nil && *b.RotationPeriod != "" {
		return errNotImplemented("rotation_period")
	}
	if b.RotationConfig != nil && *b.RotationConfig != "" {
		return errNotImplemented("rotation_config")
	}
	if b.RotationFuncURN != nil && *b.RotationFuncURN != "" {
		return errNotImplemented("rotation_func_urn")
	}

	var desc string
	if b.Description != nil {
		if len(*b.Description) > maxDescriptionBytes {
			return errParam
		}
		desc = *b.Description
	}

	rawVal, isBin, err := decodeSecretValue(b.SecretString, b.SecretBinary)
	if err != nil {
		return err
	}
	defer clear(rawVal)

	epID := "0"
	if b.EnterpriseProjectID != nil && *b.EnterpriseProjectID != "" {
		if !epIDRE.MatchString(*b.EnterpriseProjectID) {
			return errParam
		}
		epID = *b.EnterpriseProjectID
	}

	subs, err := parseEventSubscriptions(b.EventSubscriptions)
	if err != nil {
		return err
	}

	var kmsKeyID string
	if b.KMSKeyID != nil {
		kmsKeyID = *b.KMSKeyID
	}
	resolvedKeyID, plainKey, sealedKey, err := s.newVersionDataKey(r, t.Region, kmsKeyID)
	if err != nil {
		return err
	}
	defer clear(plainKey)

	s.mu.Lock()
	sec, err := func() (Secret, error) {
		defer s.mu.Unlock()

		if _, err := s.secrets(t).Get(ctx, b.Name); err == nil {
			return Secret{}, errSecretExists
		} else if !errors.Is(err, store.ErrNotFound) {
			return Secret{}, err
		}

		existing, err := s.secrets(t).List(ctx, nil)
		if err != nil {
			return Secret{}, err
		}
		if !s.quotas.Allows(quota.CSMSSecret, len(existing), 1) {
			return Secret{}, errSecretQuota
		}

		secID := s.ids.UUID()
		now := s.nowMillis()
		ct, err := seal(plainKey, secID, "v1", rawVal)
		if err != nil {
			return Secret{}, err
		}

		ver := Version{
			ID:         "v1",
			SecretID:   secID,
			KMSKeyID:   resolvedKeyID,
			Binary:     isBin,
			SealedKey:  sealedKey,
			Ciphertext: ct,
			CreatedAt:  now,
		}
		if err := s.versions(t).Put(ctx, versionStoreKey(b.Name, "v1"), ver); err != nil {
			return Secret{}, err
		}

		sec := Secret{
			ID:                  secID,
			Name:                b.Name,
			State:               stateEnabled,
			KMSKeyID:            resolvedKeyID,
			Description:         desc,
			SecretType:          secretTypeCommon,
			EnterpriseProjectID: epID,
			EventSubscriptions:  subs,
			Stages: map[string]Stage{
				stageCurrent: {VersionID: "v1", UpdatedAt: now},
			},
			NextVersion: 2,
			Tags:        []Tag{},
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.secrets(t).Create(ctx, b.Name, sec); err != nil {
			if errors.Is(err, store.ErrExists) {
				return Secret{}, errSecretExists
			}
			return Secret{}, err
		}
		return sec, nil
	}()
	if err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret created",
		"secret_id", sec.ID,
		"kms_key_id", sec.KMSKeyID,
	)
	return httpx.WriteJSON(w, http.StatusOK, secretResponse{
		Secret: toSecretView(sec, s.accountID(ctx)),
	})
}

func (s *Service) handleListSecrets(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	q := r.URL.Query()

	limit := defaultListLimit
	if rawLimit := q.Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 || n > maxListLimit {
			return errParam
		}
		limit = n
	}

	marker := q.Get("marker")
	if marker != "" && !nameRE.MatchString(marker) {
		return errParam
	}

	eventName := q.Get("event_name")
	if eventName != "" && !nameRE.MatchString(eventName) {
		return errParam
	}

	if ws := q.Get("with_shared"); ws != "" && ws != "true" && ws != "false" {
		return errParam
	}

	if eventName != "" {
		return httpx.WriteJSON(w, http.StatusOK, listSecretsResponse{
			Secrets:  []secretView{},
			PageInfo: pageInfoView{CurrentCount: 0},
		})
	}

	all, err := s.secrets(t).List(ctx, nil)
	if err != nil {
		return err
	}

	start := 0
	if marker != "" {
		idx := -1
		for i, sec := range all {
			if sec.Name == marker {
				idx = i
				break
			}
		}
		if idx < 0 {
			return errParam
		}
		start = idx + 1
	}

	var page []Secret
	if start < len(all) {
		end := start + limit
		if end > len(all) {
			end = len(all)
		}
		page = all[start:end]
	}

	acctID := s.accountID(ctx)
	views := make([]secretView, len(page))
	for i, sec := range page {
		views[i] = toSecretView(sec, acctID)
	}

	info := pageInfoView{CurrentCount: len(views)}
	if len(page) > 0 {
		info.PreviousMarker = page[0].Name
		if start+len(page) < len(all) {
			info.NextMarker = page[len(page)-1].Name
		}
	}

	return httpx.WriteJSON(w, http.StatusOK, listSecretsResponse{
		Secrets:  views,
		PageInfo: info,
	})
}

func (s *Service) handleShowSecret(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	name := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(name) {
		return errParam
	}

	sec, err := s.secrets(t).Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	return httpx.WriteJSON(w, http.StatusOK, secretResponse{
		Secret: toSecretView(sec, s.accountID(ctx)),
	})
}

func (s *Service) handleUpdateSecret(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	name := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(name) {
		return errParam
	}

	var b updateSecretRequestBody
	if err := decodeJSON(r, &b); err != nil {
		return err
	}

	cur, err := s.secrets(t).Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if cur.State == statePendingDelete {
		return errScheduledDeleteState
	}

	if b.AutoRotation != nil && *b.AutoRotation {
		return errNotImplemented("auto_rotation")
	}
	if b.RotationPeriod != nil && *b.RotationPeriod != "" {
		return errNotImplemented("rotation_period")
	}
	if b.RotationFuncURN != nil && *b.RotationFuncURN != "" {
		return errNotImplemented("rotation_func_urn")
	}

	if b.Description != nil && len(*b.Description) > maxDescriptionBytes {
		return errParam
	}

	var subs []string
	if b.EventSubscriptions != nil {
		subs, err = parseEventSubscriptions(b.EventSubscriptions)
		if err != nil {
			return err
		}
	}

	var resolvedKeyID string
	if b.KMSKeyID != nil && *b.KMSKeyID != "" {
		resolvedKeyID, err = s.checkUsableKMSKey(r, t.Region, *b.KMSKeyID)
		if err != nil {
			return err
		}
	}

	s.mu.Lock()
	now := s.nowMillis()
	updated, err := s.secrets(t).Update(ctx, name, func(sec *Secret) error {
		if sec.State == statePendingDelete {
			return errScheduledDeleteState
		}
		if resolvedKeyID != "" {
			sec.KMSKeyID = resolvedKeyID
		}
		if b.Description != nil {
			sec.Description = *b.Description
		}
		if b.EventSubscriptions != nil {
			sec.EventSubscriptions = subs
		}
		sec.UpdatedAt = now
		return nil
	})
	s.mu.Unlock()
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret updated",
		"secret_id", updated.ID,
		"name", updated.Name,
		"kms_key_id", updated.KMSKeyID,
	)
	return httpx.WriteJSON(w, http.StatusOK, secretResponse{
		Secret: toSecretView(updated, s.accountID(ctx)),
	})
}

func (s *Service) handleDeleteSecret(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	name := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(name) {
		return errParam
	}

	s.mu.Lock()
	var secID string
	err := func() error {
		defer s.mu.Unlock()

		sec, err := s.secrets(t).Get(ctx, name)
		if errors.Is(err, store.ErrNotFound) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		secID = sec.ID
		s.engine.Cancel(sec.ID)

		prefix := sec.Name + "/"
		verScope := store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVersion}
		recs, err := s.store.List(ctx, verScope)
		if err != nil {
			return err
		}
		for _, rec := range recs {
			if strings.HasPrefix(rec.ID, prefix) {
				if err := s.store.Delete(ctx, verScope, rec.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
		}

		if err := s.secrets(t).Delete(ctx, sec.Name); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errNotFound
			}
			return err
		}
		return nil
	}()
	if err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret deleted",
		"secret_id", secID,
	)
	w.WriteHeader(http.StatusNoContent)
	return nil
}
