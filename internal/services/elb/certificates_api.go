package elb

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
)

type certCreateRequest struct {
	Certificate *certCreateOption `json:"certificate"`
}

type certCreateOption struct {
	AdminStateUp        *bool   `json:"admin_state_up"`
	Certificate         *string `json:"certificate"`
	Description         *string `json:"description"`
	Domain              *string `json:"domain"`
	Name                *string `json:"name"`
	PrivateKey          *string `json:"private_key"`
	ProjectID           *string `json:"project_id"`
	Type                *string `json:"type"`
	EnterpriseProjectID *string `json:"enterprise_project_id"`
	EncCertificate      *string `json:"enc_certificate"`
	EncPrivateKey       *string `json:"enc_private_key"`
	ScmCertificateID    *string `json:"scm_certificate_id"`
	Source              *string `json:"source"`
	ProtectionStatus    *string `json:"protection_status"`
	ProtectionReason    *string `json:"protection_reason"`
}

type certUpdateRequest struct {
	Certificate *certUpdateOption `json:"certificate"`
}

type certUpdateOption struct {
	Certificate      *string `json:"certificate"`
	Description      *string `json:"description"`
	Name             *string `json:"name"`
	PrivateKey       *string `json:"private_key"`
	Domain           *string `json:"domain"`
	AdminStateUp     *bool   `json:"admin_state_up"`
	EncCertificate   *string `json:"enc_certificate"`
	EncPrivateKey    *string `json:"enc_private_key"`
	ScmCertificateID *string `json:"scm_certificate_id"`
	Source           *string `json:"source"`
	ProtectionStatus *string `json:"protection_status"`
	ProtectionReason *string `json:"protection_reason"`
}

// certWire matches SDK model CertificateInfo field-for-field.
type certWire struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	Type                    string   `json:"type"`
	Domain                  string   `json:"domain"`
	Certificate             string   `json:"certificate"`
	PrivateKey              string   `json:"private_key"`
	AdminStateUp            bool     `json:"admin_state_up"`
	ProjectID               string   `json:"project_id"`
	EncCertificate          string   `json:"enc_certificate"`
	EncPrivateKey           string   `json:"enc_private_key"`
	ScmCertificateID        string   `json:"scm_certificate_id"`
	CommonName              string   `json:"common_name"`
	Fingerprint             string   `json:"fingerprint"`
	SubjectAlternativeNames []string `json:"subject_alternative_names"`
	Source                  string   `json:"source"`
	ProtectionStatus        string   `json:"protection_status"`
	ProtectionReason        string   `json:"protection_reason"`
	EnterpriseProjectID     string   `json:"enterprise_project_id"`
	ExpireTime              string   `json:"expire_time"`
	CreatedAt               string   `json:"created_at"`
	UpdatedAt               string   `json:"updated_at"`
}

type certEnvelope struct {
	RequestID   string   `json:"request_id"`
	Certificate certWire `json:"certificate"`
}

type certListResponse struct {
	RequestID    string     `json:"request_id"`
	Certificates []certWire `json:"certificates"`
	PageInfo     pageInfo   `json:"page_info"`
}

func certDerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func certNonEmpty(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func certToWire(t Tenant, c certificate) certWire {
	sans := make([]string, len(c.SubjectAlternativeNames))
	copy(sans, c.SubjectAlternativeNames)

	protStatus := c.ProtectionStatus
	if protStatus == "" {
		protStatus = certDefaultProtectionStatus
	}
	ep := c.EnterpriseProjectID
	if ep == "" {
		ep = defaultEnterpriseProjectID
	}

	return certWire{
		ID:                      c.ID,
		Name:                    c.Name,
		Description:             c.Description,
		Type:                    c.Type,
		Domain:                  c.Domain,
		Certificate:             c.Certificate,
		PrivateKey:              "", // private-key echo is always off (§3.7)
		AdminStateUp:            c.AdminStateUp,
		ProjectID:               t.ProjectID,
		EncCertificate:          "",
		EncPrivateKey:           "",
		ScmCertificateID:        "",
		CommonName:              c.CommonName,
		Fingerprint:             c.Fingerprint,
		SubjectAlternativeNames: sans,
		Source:                  "",
		ProtectionStatus:        protStatus,
		ProtectionReason:        c.ProtectionReason,
		EnterpriseProjectID:     ep,
		ExpireTime:              formatTime(c.ExpireTime),
		CreatedAt:               formatTime(c.CreatedAt),
		UpdatedAt:               formatTime(c.UpdatedAt),
	}
}

func (s *Service) handleCreateCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req certCreateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Certificate == nil {
		return errInvalidInput("certificate")
	}
	opt := req.Certificate

	rec, err := s.certCreate(r.Context(), t, certCreateInput{
		Name:                certDerefString(opt.Name),
		Description:         certDerefString(opt.Description),
		Type:                certDerefString(opt.Type),
		Domain:              certDerefString(opt.Domain),
		Certificate:         certDerefString(opt.Certificate),
		PrivateKey:          certDerefString(opt.PrivateKey),
		AdminStateUp:        opt.AdminStateUp,
		EnterpriseProjectID: opt.EnterpriseProjectID,
		EncCertificate:      certDerefString(opt.EncCertificate),
		EncPrivateKey:       certDerefString(opt.EncPrivateKey),
		ScmCertificateID:    certDerefString(opt.ScmCertificateID),
		Source:              certDerefString(opt.Source),
		ProtectionStatus:    certDerefString(opt.ProtectionStatus),
		ProtectionReason:    certDerefString(opt.ProtectionReason),
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, certEnvelope{
		RequestID:   requestID(r),
		Certificate: certToWire(t, rec),
	})
}

func (s *Service) handleListCertificates(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errInvalidInput("limit")
	}
	if _, err := parseBoolQuery(q, "page_reverse"); err != nil {
		return err
	}
	adminStateUp, err := parseBoolQuery(q, "admin_state_up")
	if err != nil {
		return err
	}

	items, pi, err := s.certList(r.Context(), t, certListFilter{
		IDs:                  certNonEmpty(q["id"]),
		Names:                certNonEmpty(q["name"]),
		Descriptions:         certNonEmpty(q["description"]),
		AdminStateUp:         adminStateUp,
		Domains:              certNonEmpty(q["domain"]),
		Types:                certNonEmpty(q["type"]),
		ScmCertificateIDs:    certNonEmpty(q["scm_certificate_id"]),
		CommonNames:          certNonEmpty(q["common_name"]),
		Fingerprints:         certNonEmpty(q["fingerprint"]),
		Sources:              certNonEmpty(q["source"]),
		ProtectionStatuses:   certNonEmpty(q["protection_status"]),
		ProtectionReasons:    certNonEmpty(q["protection_reason"]),
		EnterpriseProjectIDs: certNonEmpty(q["enterprise_project_id"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]certWire, 0, len(items))
	for _, item := range items {
		out = append(out, certToWire(t, item))
	}
	return httpx.WriteJSON(w, http.StatusOK, certListResponse{
		RequestID:    requestID(r),
		Certificates: out,
		PageInfo:     pi,
	})
}

func (s *Service) handleShowCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "certificate_id")
	rec, err := s.certGet(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, certEnvelope{
		RequestID:   requestID(r),
		Certificate: certToWire(t, rec),
	})
}

func (s *Service) handleUpdateCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req certUpdateRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Certificate == nil {
		return errInvalidInput("certificate")
	}
	opt := req.Certificate
	id := chi.URLParam(r, "certificate_id")

	rec, err := s.certUpdate(r.Context(), t, id, certUpdateInput{
		Name:             opt.Name,
		Description:      opt.Description,
		Domain:           opt.Domain,
		Certificate:      opt.Certificate,
		PrivateKey:       opt.PrivateKey,
		AdminStateUp:     opt.AdminStateUp,
		EncCertificate:   opt.EncCertificate,
		EncPrivateKey:    opt.EncPrivateKey,
		ScmCertificateID: opt.ScmCertificateID,
		Source:           opt.Source,
		ProtectionStatus: opt.ProtectionStatus,
		ProtectionReason: opt.ProtectionReason,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, certEnvelope{
		RequestID:   requestID(r),
		Certificate: certToWire(t, rec),
	})
}

func (s *Service) handleDeleteCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "certificate_id")
	if err := s.certDelete(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
