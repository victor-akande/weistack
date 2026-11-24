package ecs

import (
	"math"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

// novaKeypairLimits bounds "limit" on NovaListKeypairs (1..1000, default 1000).
var novaKeypairLimits = pagination.Limits{Default: 1000, Min: 1, Max: 1000}

// Wire types mirroring huaweicloud-sdk-go-v3 services/ecs/v2/model Nova
// keypair models and DEW historical v2.1 os-keypairs documentation.

type novaEncryptionWire struct {
	Type       string `json:"type"`
	KMSKeyName string `json:"kms_key_name"`
	KMSKeyID   string `json:"kms_key_id"`
}

type novaKeyProtectionWire struct {
	PrivateKey string              `json:"private_key"`
	Encryption *novaEncryptionWire `json:"encryption"`
}

type novaCreateKeypairOption struct {
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	PublicKey     string                 `json:"public_key"`
	UserID        string                 `json:"user_id"`
	KeyProtection *novaKeyProtectionWire `json:"key_protection"`
}

type novaCreateKeypairRequest struct {
	Keypair *novaCreateKeypairOption `json:"keypair"`
}

type novaKeypairWire struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key,omitempty"`
	UserID      string `json:"user_id"`
	Type        string `json:"type,omitempty"`
}

type novaCreateKeypairResponse struct {
	Keypair novaKeypairWire `json:"keypair"`
}

type novaSimpleKeypairWire struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Type        string `json:"type,omitempty"`
}

type novaListKeypairsItem struct {
	Keypair novaSimpleKeypairWire `json:"keypair"`
}

type novaListKeypairsResponse struct {
	Keypairs []novaListKeypairsItem `json:"keypairs"`
}

type novaKeypairDetailWire struct {
	PublicKey   string  `json:"public_key"`
	Name        string  `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	CreatedAt   string  `json:"created_at"`
	Deleted     bool    `json:"deleted"`
	DeletedAt   *string `json:"deleted_at"`
	ID          int32   `json:"id"`
	UpdatedAt   *string `json:"updated_at"`
	UserID      string  `json:"user_id"`
	Type        string  `json:"type,omitempty"`
}

type novaShowKeypairResponse struct {
	Keypair novaKeypairDetailWire `json:"keypair"`
}

func (s *Service) handleNovaCreateKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if s.keypairs == nil {
		return apierr.NotImplemented("ecs", "NovaCreateKeypair")
	}

	var req novaCreateKeypairRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Keypair == nil {
		return errInvalidRequest("request body is illegal: it must contain a keypair object")
	}
	if req.Keypair.Name == "" {
		return errInvalidRequest("keypair.name is required")
	}

	in := NovaCreateKeypairInput{
		Name:      req.Keypair.Name,
		Type:      req.Keypair.Type,
		PublicKey: req.Keypair.PublicKey,
		UserID:    req.Keypair.UserID,
	}
	if req.Keypair.KeyProtection != nil {
		prot := &NovaKeyProtectionInput{
			PrivateKey: req.Keypair.KeyProtection.PrivateKey,
		}
		if req.Keypair.KeyProtection.Encryption != nil {
			prot.Encryption = &NovaEncryptionInput{
				Type:       req.Keypair.KeyProtection.Encryption.Type,
				KMSKeyName: req.Keypair.KeyProtection.Encryption.KMSKeyName,
				KMSKeyID:   req.Keypair.KeyProtection.Encryption.KMSKeyID,
			}
		}
		in.KeyProtection = prot
	}

	out, err := s.keypairs.NovaCreate(r.Context(), t.Region, t.ProjectID, in)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, novaCreateKeypairResponse{
		Keypair: novaKeypairWire{
			Fingerprint: out.Fingerprint,
			Name:        out.Name,
			PublicKey:   out.PublicKey,
			PrivateKey:  out.PrivateKey,
			UserID:      out.UserID,
			Type:        out.Type,
		},
	})
}

func (s *Service) handleNovaListKeypairs(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if s.keypairs == nil {
		return apierr.NotImplemented("ecs", "NovaListKeypairs")
	}

	page, err := pagination.ParseMarker(r.URL.Query(), novaKeypairLimits)
	if err != nil {
		return errInvalidRequest("%s", err)
	}
	kps, err := s.keypairs.NovaList(r.Context(), t.Region, t.ProjectID, page.ID, page.Limit)
	if err != nil {
		return err
	}

	items := make([]novaListKeypairsItem, 0, len(kps))
	for _, kp := range kps {
		items = append(items, novaListKeypairsItem{
			Keypair: novaSimpleKeypairWire{
				Fingerprint: kp.Fingerprint,
				Name:        kp.Name,
				PublicKey:   kp.PublicKey,
				Type:        kp.Type,
			},
		})
	}
	return httpx.WriteJSON(w, http.StatusOK, novaListKeypairsResponse{Keypairs: items})
}

func (s *Service) handleNovaShowKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if s.keypairs == nil {
		return apierr.NotImplemented("ecs", "NovaShowKeypair")
	}

	kp, err := s.keypairs.NovaGet(r.Context(), t.Region, t.ProjectID, chi.URLParam(r, "keypair_name"))
	if err != nil {
		return err
	}

	createdAt := time.UnixMilli(kp.CreatedAt).UTC().Format(timeLayout)
	var updatedAt *string
	if kp.UpdatedAt > 0 {
		u := time.UnixMilli(kp.UpdatedAt).UTC().Format(timeLayout)
		updatedAt = &u
	}

	return httpx.WriteJSON(w, http.StatusOK, novaShowKeypairResponse{
		Keypair: novaKeypairDetailWire{
			PublicKey:   kp.PublicKey,
			Name:        kp.Name,
			Fingerprint: kp.Fingerprint,
			CreatedAt:   createdAt,
			Deleted:     kp.Deleted,
			DeletedAt:   nil,
			ID:          clampKeypairID(kp.ID),
			UpdatedAt:   updatedAt,
			UserID:      kp.UserID,
			Type:        kp.Type,
		},
	})
}

func (s *Service) handleNovaDeleteKeypair(w http.ResponseWriter, r *http.Request, t Tenant) error {
	if s.keypairs == nil {
		return apierr.NotImplemented("ecs", "NovaDeleteKeypair")
	}

	if err := s.keypairs.NovaDelete(r.Context(), t.Region, t.ProjectID, chi.URLParam(r, "keypair_name")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func clampKeypairID(id int64) int32 {
	if id > math.MaxInt32 {
		return math.MaxInt32
	}
	if id < math.MinInt32 {
		return math.MinInt32
	}
	return int32(id)
}
