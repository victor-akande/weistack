package csms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/store"
)

func (s *Service) listVersionsForSecret(ctx context.Context, t Tenant, sec Secret) ([]Version, error) {
	scope := store.Scope{Region: t.Region, ProjectID: t.ProjectID, Kind: kindVersion}
	recs, err := s.store.List(ctx, scope)
	if err != nil {
		return nil, err
	}
	prefix := sec.Name + "/"
	out := make([]Version, 0, len(recs))
	for _, rec := range recs {
		if !strings.HasPrefix(rec.ID, prefix) {
			continue
		}
		var v Version
		if err := json.Unmarshal(rec.Data, &v); err != nil {
			return nil, fmt.Errorf("csms: decoding version %s: %w", rec.ID, err)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return parseVersionNum(out[i].ID) < parseVersionNum(out[j].ID)
	})
	return out, nil
}

func (s *Service) handleCreateSecretVersion(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(secretName) {
		return errParam
	}

	var b struct {
		SecretBinary  *string   `json:"secret_binary"`
		SecretString  *string   `json:"secret_string"`
		VersionStages *[]string `json:"version_stages"`
		ExpireTime    *int64    `json:"expire_time"`
	}
	if err := decodeJSON(r, &b); err != nil {
		return err
	}

	rawVal, isBin, err := decodeSecretValue(b.SecretString, b.SecretBinary)
	if err != nil {
		return err
	}
	defer clear(rawVal)

	if b.VersionStages != nil {
		stages := *b.VersionStages
		if len(stages) == 0 {
			return errParam
		}
		if len(stages) > maxStagesPerSecret {
			return errStageQuota
		}
		seen := make(map[string]struct{}, len(stages))
		for _, st := range stages {
			if !nameRE.MatchString(st) {
				return errParam
			}
			if _, dup := seen[st]; dup {
				return errParam
			}
			seen[st] = struct{}{}
		}
	}
	if b.ExpireTime != nil && *b.ExpireTime < 0 {
		return errParam
	}

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if sec.State != stateEnabled {
		return errScheduledDeleteState
	}

	resolvedKeyID, plainKey, sealedKey, err := s.newVersionDataKey(r, t.Region, sec.KMSKeyID)
	if err != nil {
		return err
	}
	defer clear(plainKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	sec, err = s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if sec.State != stateEnabled {
		return errScheduledDeleteState
	}

	next := sec.NextVersion
	if next < 1 {
		next = 1
	}
	verID := fmt.Sprintf("v%d", next)
	now := s.nowMillis()

	newStages := make(map[string]Stage, len(sec.Stages)+2)
	for k, v := range sec.Stages {
		newStages[k] = v
	}

	targetStages := []string{stageCurrent}
	if b.VersionStages != nil {
		targetStages = *b.VersionStages
	}

	hasCurrent := slices.Contains(targetStages, stageCurrent)
	hasPrevious := slices.Contains(targetStages, stagePrevious)
	if hasCurrent && !hasPrevious {
		if prevCur, ok := newStages[stageCurrent]; ok && prevCur.VersionID != "" && prevCur.VersionID != verID {
			newStages[stagePrevious] = Stage{VersionID: prevCur.VersionID, UpdatedAt: now}
		}
	}
	for _, stName := range targetStages {
		newStages[stName] = Stage{VersionID: verID, UpdatedAt: now}
	}
	if len(newStages) > maxStagesPerSecret {
		return errStageQuota
	}

	existing, err := s.listVersionsForSecret(ctx, t, sec)
	if err != nil {
		return err
	}
	for len(existing) >= maxVersionsPerSecret {
		pruneIdx := -1
		for i, v := range existing {
			if len(stagesForVersion(newStages, v.ID)) == 0 {
				pruneIdx = i
				break
			}
		}
		if pruneIdx < 0 {
			return errParam
		}
		if err := s.versions(t).Delete(ctx, versionStoreKey(sec.Name, existing[pruneIdx].ID)); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		existing = slices.Delete(existing, pruneIdx, pruneIdx+1)
	}

	ct, err := seal(plainKey, sec.ID, verID, rawVal)
	if err != nil {
		return err
	}

	var exp int64
	if b.ExpireTime != nil {
		exp = *b.ExpireTime
	}
	ver := Version{
		ID:         verID,
		SecretID:   sec.ID,
		KMSKeyID:   resolvedKeyID,
		Binary:     isBin,
		SealedKey:  sealedKey,
		Ciphertext: ct,
		ExpireAt:   exp,
		CreatedAt:  now,
	}
	if err := s.versions(t).Put(ctx, versionStoreKey(sec.Name, verID), ver); err != nil {
		return err
	}

	sec.Stages = newStages
	sec.NextVersion = next + 1
	sec.UpdatedAt = now
	if err := s.secrets(t).Put(ctx, sec.Name, sec); err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret version created", "secret_name", sec.Name, "version_id", ver.ID)
	return httpx.WriteJSON(w, http.StatusOK, versionMetadataResponse{
		VersionMetadata: toVersionMetadataView(sec, ver),
	})
}

func (s *Service) handleListSecretVersions(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(secretName) {
		return errParam
	}

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
	if marker != "" && !versionIDRE.MatchString(marker) {
		return errParam
	}

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	all, err := s.listVersionsForSecret(ctx, t, sec)
	if err != nil {
		return err
	}

	start := 0
	if marker != "" {
		idx := slices.IndexFunc(all, func(v Version) bool { return v.ID == marker })
		if idx < 0 {
			return errParam
		}
		start = idx + 1
	}

	end := min(start+limit, len(all))
	page := all[start:end]

	var nextMarker, prevMarker string
	if end < len(all) && len(page) > 0 {
		nextMarker = page[len(page)-1].ID
	}
	if start > 0 && len(page) > 0 {
		prevMarker = page[0].ID
	}

	views := make([]versionMetadataView, 0, len(page))
	for _, v := range page {
		views = append(views, toVersionMetadataView(sec, v))
	}

	return httpx.WriteJSON(w, http.StatusOK, listVersionsResponse{
		VersionMetadatas: views,
		PageInfo: pageInfoView{
			NextMarker:     nextMarker,
			PreviousMarker: prevMarker,
			CurrentCount:   len(views),
		},
	})
}

func (s *Service) handleShowSecretVersion(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	if !nameRE.MatchString(secretName) {
		return errParam
	}
	versionID := chi.URLParam(r, "version_id")
	if versionID != "latest" && !versionIDRE.MatchString(versionID) {
		return errParam
	}

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if sec.State != stateEnabled {
		return errStateNotEnabled
	}

	var ver Version
	if versionID == "latest" {
		all, err := s.listVersionsForSecret(ctx, t, sec)
		if err != nil {
			return err
		}
		if len(all) == 0 {
			return errNotFound
		}
		ver = all[len(all)-1]
	} else {
		ver, err = s.versions(t).Get(ctx, versionStoreKey(sec.Name, versionID))
		if errors.Is(err, store.ErrNotFound) {
			return errNotFound
		}
		if err != nil {
			return err
		}
	}

	plainKey, err := s.openVersionDataKey(r, t.Region, s.accountID(ctx), ver.KMSKeyID, ver.SealedKey)
	if err != nil {
		return err
	}
	defer clear(plainKey)

	plainVal, err := open(plainKey, sec.ID, ver.ID, ver.Ciphertext)
	if err != nil {
		return err
	}
	defer clear(plainVal)

	s.mu.Lock()
	curSec, err := s.secrets(t).Get(ctx, sec.Name)
	if err == nil {
		curSec.LastUsedAt = s.nowMillis()
		if putErr := s.secrets(t).Put(ctx, curSec.Name, curSec); putErr != nil {
			s.mu.Unlock()
			return putErr
		}
		sec = curSec
	} else if !errors.Is(err, store.ErrNotFound) {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	view := versionView{
		VersionMetadata: toVersionMetadataView(sec, ver),
	}
	if ver.Binary {
		b64 := base64.StdEncoding.EncodeToString(plainVal)
		view.SecretBinary = &b64
	} else {
		str := string(plainVal)
		view.SecretString = &str
	}

	s.log.DebugContext(ctx, "csms secret version read", "secret_name", sec.Name, "version_id", ver.ID)
	return httpx.WriteJSON(w, http.StatusOK, versionResponse{Version: view})
}

func (s *Service) handleUpdateVersion(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	versionID := chi.URLParam(r, "version_id")
	if !nameRE.MatchString(secretName) || !versionIDRE.MatchString(versionID) {
		return errParam
	}

	var b struct {
		ExpireTime *int64 `json:"expire_time"`
	}
	if err := decodeJSON(r, &b); err != nil {
		return err
	}
	if b.ExpireTime == nil || *b.ExpireTime < 0 {
		return errParam
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if sec.State != stateEnabled {
		return errScheduledDeleteState
	}

	ver, err := s.versions(t).Get(ctx, versionStoreKey(sec.Name, versionID))
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	ver.ExpireAt = *b.ExpireTime
	if err := s.versions(t).Put(ctx, versionStoreKey(sec.Name, ver.ID), ver); err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret version updated", "secret_name", sec.Name, "version_id", ver.ID)
	return httpx.WriteJSON(w, http.StatusOK, versionMetadataResponse{
		VersionMetadata: toVersionMetadataView(sec, ver),
	})
}

func (s *Service) handleShowSecretStage(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	stageName := chi.URLParam(r, "stage_name")
	if !nameRE.MatchString(secretName) || !nameRE.MatchString(stageName) {
		return errParam
	}

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	st, ok := sec.Stages[stageName]
	if !ok {
		return errNotFound
	}

	return httpx.WriteJSON(w, http.StatusOK, stageResponse{
		Stage: toStageView(sec.Name, stageName, st),
	})
}

func (s *Service) handleUpdateSecretStage(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	stageName := chi.URLParam(r, "stage_name")
	if !nameRE.MatchString(secretName) || !nameRE.MatchString(stageName) {
		return errParam
	}

	var b struct {
		VersionID string `json:"version_id"`
	}
	if err := decodeJSON(r, &b); err != nil {
		return err
	}
	if !versionIDRE.MatchString(b.VersionID) {
		return errParam
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if sec.State != stateEnabled {
		return errScheduledDeleteState
	}

	ver, err := s.versions(t).Get(ctx, versionStoreKey(sec.Name, b.VersionID))
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	} else if err != nil {
		return err
	}

	now := s.nowMillis()
	newStages := make(map[string]Stage, len(sec.Stages)+1)
	for k, v := range sec.Stages {
		newStages[k] = v
	}
	if stageName == stageCurrent {
		if prevCur, ok := newStages[stageCurrent]; ok && prevCur.VersionID != "" && prevCur.VersionID != ver.ID {
			newStages[stagePrevious] = Stage{VersionID: prevCur.VersionID, UpdatedAt: now}
		}
	}
	st := Stage{VersionID: ver.ID, UpdatedAt: now}
	newStages[stageName] = st
	if len(newStages) > maxStagesPerSecret {
		return errStageQuota
	}

	sec.Stages = newStages
	sec.UpdatedAt = now
	if err := s.secrets(t).Put(ctx, sec.Name, sec); err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret stage updated", "secret_id", sec.ID, "version_id", ver.ID)
	return httpx.WriteJSON(w, http.StatusOK, stageResponse{
		Stage: toStageView(sec.Name, stageName, st),
	})
}

func (s *Service) handleDeleteSecretStage(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	secretName := chi.URLParam(r, "secret_name")
	stageName := chi.URLParam(r, "stage_name")
	if !nameRE.MatchString(secretName) || !nameRE.MatchString(stageName) {
		return errParam
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sec, err := s.secrets(t).Get(ctx, secretName)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if sec.State != stateEnabled {
		return errScheduledDeleteState
	}

	if stageName == stageCurrent || stageName == stagePrevious {
		return errSystemStage
	}

	if _, ok := sec.Stages[stageName]; !ok {
		return errNotFound
	}

	delete(sec.Stages, stageName)
	sec.UpdatedAt = s.nowMillis()
	if err := s.secrets(t).Put(ctx, sec.Name, sec); err != nil {
		return err
	}

	s.log.DebugContext(ctx, "csms secret stage deleted", "secret_id", sec.ID)
	w.WriteHeader(http.StatusNoContent)
	return nil
}
