package kps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/ssh"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	maxKeypairNameLen = 255
	maxDescriptionLen = 255
	defaultListLimit  = 1000
	maxListLimit      = 1000
	rsaKeyBits        = 2048
)

// validKeypairName reports whether name is 1..255 ASCII letters, digits,
// underscores or hyphens, matching Huawei Cloud's key pair name constraint.
func validKeypairName(name string) bool {
	if len(name) == 0 || len(name) > maxKeypairNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func generateRSAKeypair() (publicKey, privateKeyPEM, fingerprint, algorithm string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return "", "", "", "", err
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", "", "", err
	}
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	privPEM := string(pem.EncodeToMemory(privBlock))
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	return pubStr, privPEM, ssh.FingerprintLegacyMD5(pub), pub.Type(), nil
}

func (s *Service) createKeypair(ctx context.Context, t Tenant, req createKeypairAction) (Keypair, string, error) {
	if !validKeypairName(req.Name) {
		return Keypair{}, "", errParam
	}

	kpType := req.Type
	if kpType == "" {
		kpType = "ssh"
	}
	if kpType != "ssh" && kpType != "x509" {
		return Keypair{}, "", errParam
	}

	scope := req.Scope
	if scope == "" {
		scope = "user"
	}
	if scope != "user" && scope != "domain" {
		return Keypair{}, "", errParam
	}

	if req.KeyProtection != nil {
		if req.KeyProtection.Encryption == nil {
			return Keypair{}, "", errParam
		}
		if req.PublicKey == "" && req.KeyProtection.PrivateKey != "" {
			return Keypair{}, "", errParam
		}
		if req.PublicKey != "" && req.KeyProtection.PrivateKey == "" {
			return Keypair{}, "", errParam
		}
	}

	userID := req.UserID
	if userID == "" {
		userID = s.callerUserID(ctx)
	}

	var (
		pubKeyStr          string
		fingerprint        string
		algorithm          string
		returnedPrivateKey string
	)

	if req.PublicKey != "" {
		trimmed := strings.TrimSpace(req.PublicKey)
		pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
		if err != nil || len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
			return Keypair{}, "", errParam
		}
		pubKeyStr = trimmed
		fingerprint = ssh.FingerprintLegacyMD5(pub)
		algorithm = pub.Type()
	}

	// Fast-path duplicate check before spending CPU on RSA key generation or KMS.
	if _, err := s.keypairs(t).Get(ctx, req.Name); err == nil {
		return Keypair{}, "", errDuplicateKeypair(req.Name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return Keypair{}, "", err
	}

	if req.PublicKey == "" {
		var err error
		pubKeyStr, returnedPrivateKey, fingerprint, algorithm, err = generateRSAKeypair()
		if err != nil {
			return Keypair{}, "", err
		}
	}

	kp := Keypair{
		Name:        req.Name,
		Type:        kpType,
		Scope:       scope,
		UserID:      userID,
		PublicKey:   pubKeyStr,
		Fingerprint: fingerprint,
		Algorithm:   algorithm,
	}

	if req.KeyProtection != nil {
		var privToSeal string
		if req.PublicKey == "" {
			privToSeal = returnedPrivateKey
		} else {
			if err := verifyKeyPairMatch(kp.PublicKey, req.KeyProtection.PrivateKey); err != nil {
				return Keypair{}, "", err
			}
			privToSeal = req.KeyProtection.PrivateKey
		}
		if err := s.sealPrivateKey(ctx, t, &kp, privToSeal, req.KeyProtection.Encryption); err != nil {
			return Keypair{}, "", err
		}
	}

	// Authoritative uniqueness check, per-project sequence ID, and insert.
	s.mu.Lock()
	existing, err := s.keypairs(t).List(ctx, nil)
	if err != nil {
		s.mu.Unlock()
		return Keypair{}, "", err
	}
	var maxID int64
	for _, ex := range existing {
		if ex.Name == req.Name {
			s.mu.Unlock()
			return Keypair{}, "", errDuplicateKeypair(req.Name)
		}
		if ex.ID > maxID {
			maxID = ex.ID
		}
	}
	kp.ID = maxID + 1
	kp.CreatedAt = s.clock().UTC().UnixMilli()
	kp.UpdatedAt = 0
	err = s.keypairs(t).Create(ctx, kp.Name, kp)
	s.mu.Unlock()
	if errors.Is(err, store.ErrExists) {
		return Keypair{}, "", errDuplicateKeypair(req.Name)
	}
	if err != nil {
		return Keypair{}, "", err
	}

	s.log.InfoContext(ctx, "kps keypair created",
		"keypair_id", kp.ID,
		"name", sanitizeLog(kp.Name),
		"scope", sanitizeLog(kp.Scope),
		"algorithm", kp.Algorithm,
		"protected", len(kp.SealedKey) > 0,
	)
	return kp, returnedPrivateKey, nil
}

func (s *Service) getKeypair(ctx context.Context, t Tenant, name string) (Keypair, error) {
	kp, err := s.keypairs(t).Get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return Keypair{}, errNotFound
	}
	if err != nil {
		return Keypair{}, err
	}
	if !s.isVisible(ctx, kp) {
		return Keypair{}, errNotFound
	}
	return kp, nil
}

func (s *Service) listKeypairs(ctx context.Context, t Tenant, marker string, limit int) ([]Keypair, string, string, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	all, err := s.keypairs(t).List(ctx, func(kp Keypair) bool {
		return s.isVisible(ctx, kp)
	})
	if err != nil {
		return nil, "", "", err
	}

	start := 0
	if marker != "" {
		found := -1
		for i, kp := range all {
			if kp.Name == marker {
				found = i + 1
				break
			}
		}
		if found < 0 || found >= len(all) {
			return []Keypair{}, "", "", nil
		}
		start = found
	}

	end := len(all)
	if limit < end-start {
		end = start + limit
	}
	page := all[start:end]

	var nextMarker, prevMarker string
	if end < len(all) && len(page) > 0 {
		nextMarker = page[len(page)-1].Name
	}
	if marker != "" && len(page) > 0 {
		prevMarker = page[0].Name
	}
	return page, nextMarker, prevMarker, nil
}

func (s *Service) deleteKeypair(ctx context.Context, t Tenant, name string) error {
	if _, err := s.getKeypair(ctx, t, name); err != nil {
		return err
	}
	err := s.keypairs(t).Delete(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	s.log.InfoContext(ctx, "kps keypair deleted", "name", sanitizeLog(name))
	return nil
}

// sanitizeLog strips line breaks before structured logging.
func sanitizeLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	return strings.ReplaceAll(s, "\r", "")
}

func (s *Service) handleCreateKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createKeypairRequest
	if err := httpx.DecodeJSON(r, &req); err != nil || req.Keypair == nil {
		return errParam
	}
	kp, privKey, err := s.createKeypair(r.Context(), t, *req.Keypair)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, createKeypairResponse{
		Keypair: createKeypairResp{
			Name:        kp.Name,
			Type:        kp.Type,
			PublicKey:   kp.PublicKey,
			PrivateKey:  privKey,
			Fingerprint: kp.Fingerprint,
			UserID:      kp.UserID,
		},
	})
}

func (s *Service) handleListKeypairs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	page, err := pagination.ParseMarker(r.URL.Query(), pagination.Limits{
		Default: defaultListLimit,
		Min:     1,
		Max:     maxListLimit,
	})
	if err != nil {
		return errParam
	}

	kps, nextMarker, prevMarker, err := s.listKeypairs(r.Context(), t, page.ID, page.Limit)
	if err != nil {
		return err
	}

	items := make([]keypairItem, 0, len(kps))
	for _, kp := range kps {
		items = append(items, keypairItem{
			Keypair: keypairSummary{
				Name:            kp.Name,
				Type:            kp.Type,
				Scope:           kp.Scope,
				PublicKey:       kp.PublicKey,
				Fingerprint:     kp.Fingerprint,
				IsKeyProtection: len(kp.SealedKey) > 0,
				FrozenState:     "0",
			},
		})
	}

	return httpx.WriteJSON(w, http.StatusOK, listKeypairsResponse{
		Keypairs: items,
		PageInfo: pageInfoWire{
			NextMarker:     nextMarker,
			PreviousMarker: prevMarker,
			CurrentCount:   int32(len(items)), //nolint:gosec // bounded by maxListLimit (1000)
		},
	})
}

func (s *Service) handleListKeypairDetail(w http.ResponseWriter, r *http.Request, t Tenant) error {
	name := chi.URLParam(r, "keypair_name")
	kp, err := s.getKeypair(r.Context(), t, name)
	if err != nil {
		return err
	}

	var updateTime *int64
	if kp.UpdatedAt > 0 {
		u := kp.UpdatedAt
		updateTime = &u
	}

	return httpx.WriteJSON(w, http.StatusOK, listKeypairDetailResponse{
		Keypair: keypairDetailWire{
			Name:            kp.Name,
			ID:              kp.ID,
			Type:            kp.Type,
			Scope:           kp.Scope,
			PublicKey:       kp.PublicKey,
			Fingerprint:     kp.Fingerprint,
			IsKeyProtection: len(kp.SealedKey) > 0,
			Deleted:         false,
			Description:     kp.Description,
			UserID:          kp.UserID,
			CreateTime:      kp.CreatedAt,
			DeleteTime:      nil,
			UpdateTime:      updateTime,
			FrozenState:     0,
			KeyID:           kp.KMSKeyID,
			Algorithm:       kp.Algorithm,
		},
	})
}

func (s *Service) handleUpdateKeypairDescription(w http.ResponseWriter, r *http.Request, t Tenant) error {
	name := chi.URLParam(r, "keypair_name")
	var req updateDescriptionRequest
	if err := httpx.DecodeJSON(r, &req); err != nil || req.Keypair == nil || req.Keypair.Description == nil {
		return errParam
	}
	desc := *req.Keypair.Description
	if len(desc) > maxDescriptionLen {
		return errParam
	}

	if _, err := s.getKeypair(r.Context(), t, name); err != nil {
		return err
	}

	now := s.clock().UTC().UnixMilli()
	_, err := s.keypairs(t).Update(r.Context(), name, func(kp *Keypair) error {
		if !s.isVisible(r.Context(), *kp) {
			return errNotFound
		}
		kp.Description = desc
		kp.UpdatedAt = now
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (s *Service) handleDeleteKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	name := chi.URLParam(r, "keypair_name")
	if err := s.deleteKeypair(r.Context(), t, name); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
