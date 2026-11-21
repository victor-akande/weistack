package elb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" //nolint:gosec // X.509 SHA-1 fingerprint is part of the ELB API
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	certTypeServer              = "server"
	certTypeClient              = "client"
	certTypeServerSM            = "server_sm"
	certDefaultProtectionStatus = "nonProtection"
	certMaxCertLen              = 20000
	certMaxKeyLen               = 8192
	certMaxChainLen             = 11
	certMaxDomainLen            = 10000
	certMaxDomains              = 100
	certVaultLabelPrefix        = "weistack:elb:cert:"
)

type certCreateInput struct {
	Name                string
	Description         string
	Type                string
	Domain              string
	Certificate         string
	PrivateKey          string
	AdminStateUp        *bool
	EnterpriseProjectID *string
	EncCertificate      string
	EncPrivateKey       string
	ScmCertificateID    string
	Source              string
	ProtectionStatus    string
	ProtectionReason    string
}

type certUpdateInput struct {
	Name             *string
	Description      *string
	Domain           *string
	Certificate      *string
	PrivateKey       *string
	AdminStateUp     *bool
	EncCertificate   *string
	EncPrivateKey    *string
	ScmCertificateID *string
	Source           *string
	ProtectionStatus *string
	ProtectionReason *string
}

type certListFilter struct {
	IDs                  []string
	Names                []string
	Descriptions         []string
	AdminStateUp         *bool
	Domains              []string
	Types                []string
	ScmCertificateIDs    []string
	CommonNames          []string
	Fingerprints         []string
	Sources              []string
	ProtectionStatuses   []string
	ProtectionReasons    []string
	EnterpriseProjectIDs []string
	Page                 pagination.Marker
}

type certDerived struct {
	ExpireTime              time.Time
	CommonName              string
	SubjectAlternativeNames []string
	Fingerprint             string
}

func certValidProtectionStatus(v string) bool {
	return v == "" || v == "nonProtection" || v == "consoleProtection"
}

func certValidProtectionReason(v string) bool {
	return utf8.RuneCountInString(v) <= 255 && !strings.ContainsAny(v, "<>")
}

func certIsASCIIAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func certValidDomainLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if !certIsASCIIAlnum(label[0]) || !certIsASCIIAlnum(label[len(label)-1]) {
		return false
	}
	for i := range len(label) {
		c := label[i]
		if !certIsASCIIAlnum(c) && c != '-' {
			return false
		}
	}
	return true
}

func certValidDomainName(name string) bool {
	if name == "" {
		return false
	}
	host := strings.TrimPrefix(name, "*.")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !certValidDomainLabel(label) {
			return false
		}
	}
	return true
}

func certValidDomainList(s string) bool {
	if utf8.RuneCountInString(s) > certMaxDomainLen {
		return false
	}
	parts := strings.Split(s, ",")
	if len(parts) > certMaxDomains {
		return false
	}
	for _, part := range parts {
		if !certValidDomainName(part) {
			return false
		}
	}
	return true
}

func certParsePEMChain(pemStr string, invalidErr func() *apierr.Error) (*x509.Certificate, error) {
	rest := []byte(pemStr)
	var leaf *x509.Certificate
	count := 0

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) > 0 {
				return nil, invalidErr()
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, invalidErr()
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalidErr()
		}
		count++
		if count > certMaxChainLen {
			return nil, errInvalidInput("certificate")
		}
		if leaf == nil {
			leaf = parsed
		}
	}

	if leaf == nil {
		return nil, invalidErr()
	}
	return leaf, nil
}

func certParsePrivateKey(pemStr string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(pemStr))
	if block == nil || len(bytes.TrimSpace(rest)) > 0 {
		return nil, errInvalidCertificate()
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return nil, errInvalidCertificate()
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := k.(crypto.Signer); ok {
			return signer, nil
		}
	}
	return nil, errInvalidCertificate()
}

func certKeyMatchesLeaf(leaf *x509.Certificate, signer crypto.Signer) bool {
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return pub.Equal(leaf.PublicKey)
}

func certDerive(leaf *x509.Certificate) certDerived {
	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}
	sum := sha1.Sum(leaf.Raw) //nolint:gosec // X.509 SHA-1 fingerprint is part of the ELB API
	return certDerived{
		ExpireTime:              leaf.NotAfter.UTC().Truncate(time.Second),
		CommonName:              leaf.Subject.CommonName,
		SubjectAlternativeNames: sans,
		Fingerprint:             fmt.Sprintf("%x", sum),
	}
}

func certValidateServerPair(certPEM, keyPEM string) (certDerived, error) {
	if certPEM == "" || utf8.RuneCountInString(certPEM) > certMaxCertLen {
		return certDerived{}, errInvalidInput("certificate")
	}
	if keyPEM == "" || utf8.RuneCountInString(keyPEM) > certMaxKeyLen {
		return certDerived{}, errInvalidInput("private_key")
	}
	leaf, err := certParsePEMChain(certPEM, errInvalidCertificate)
	if err != nil {
		return certDerived{}, err
	}
	signer, err := certParsePrivateKey(keyPEM)
	if err != nil {
		return certDerived{}, err
	}
	if !certKeyMatchesLeaf(leaf, signer) {
		return certDerived{}, errInvalidCertificate()
	}
	return certDerive(leaf), nil
}

func certValidateCA(certPEM string) (certDerived, error) {
	if certPEM == "" || utf8.RuneCountInString(certPEM) > certMaxCertLen {
		return certDerived{}, errInvalidInput("certificate")
	}
	leaf, err := certParsePEMChain(certPEM, errInvalidCACertificate)
	if err != nil {
		return certDerived{}, err
	}
	if !leaf.IsCA {
		return certDerived{}, errInvalidCACertificate()
	}
	return certDerive(leaf), nil
}

func (s *Service) certIsUsedByListener(ctx context.Context, t Tenant, certID string) (bool, error) {
	listeners, err := s.listeners(t).List(ctx, nil)
	if err != nil {
		return false, err
	}
	for _, l := range listeners {
		if l.DefaultTLSContainerRef == certID || l.ClientCATLSContainerRef == certID || slices.Contains(l.SNIContainerRefs, certID) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) certCreate(ctx context.Context, t Tenant, in certCreateInput) (certificate, error) {
	certType := in.Type
	if certType == "" {
		certType = certTypeServer
	}
	switch certType {
	case certTypeServer, certTypeClient:
	case certTypeServerSM:
		return certificate{}, errNotImplemented("server_sm")
	default:
		return certificate{}, errInvalidInput("type")
	}

	if in.EncCertificate != "" {
		return certificate{}, errNotImplemented("enc_certificate")
	}
	if in.EncPrivateKey != "" {
		return certificate{}, errNotImplemented("enc_private_key")
	}
	if in.ScmCertificateID != "" {
		return certificate{}, errNotImplemented("scm_certificate_id")
	}
	if in.Source == "scm" {
		return certificate{}, errNotImplemented("scm")
	}
	if in.Source != "" {
		return certificate{}, errInvalidInput("source")
	}

	if !validName(in.Name) {
		return certificate{}, errInvalidInput("name")
	}
	if !validDescription(in.Description) {
		return certificate{}, errInvalidInput("description")
	}
	ep := defaultEnterpriseProjectID
	if in.EnterpriseProjectID != nil {
		if !validEnterpriseProjectID(*in.EnterpriseProjectID) {
			return certificate{}, errInvalidInput("enterprise_project_id")
		}
		ep = *in.EnterpriseProjectID
	}
	if !certValidProtectionStatus(in.ProtectionStatus) {
		return certificate{}, errInvalidInput("protection_status")
	}
	if !certValidProtectionReason(in.ProtectionReason) {
		return certificate{}, errInvalidInput("protection_reason")
	}
	if in.Domain != "" && !certValidDomainList(in.Domain) {
		return certificate{}, errInvalidInput("domain")
	}

	var derived certDerived
	var err error
	if certType == certTypeServer {
		derived, err = certValidateServerPair(in.Certificate, in.PrivateKey)
	} else {
		derived, err = certValidateCA(in.Certificate)
	}
	if err != nil {
		return certificate{}, err
	}

	id := s.ids.UUID()
	var sealedKey []byte
	if certType == certTypeServer {
		sealedKey, err = s.vault.Seal(in.PrivateKey, certVaultLabelPrefix+id)
		if err != nil {
			return certificate{}, err
		}
	}

	domain := in.Domain
	if domain == "" {
		domain = derived.CommonName
	}
	adminUp := true
	if in.AdminStateUp != nil {
		adminUp = *in.AdminStateUp
	}
	protStatus := in.ProtectionStatus
	if protStatus == "" {
		protStatus = certDefaultProtectionStatus
	}

	now := s.nowUTC()
	rec := certificate{
		ID:                      id,
		Name:                    in.Name,
		Description:             in.Description,
		Type:                    certType,
		Domain:                  domain,
		Certificate:             in.Certificate,
		SealedPrivateKey:        sealedKey,
		AdminStateUp:            adminUp,
		CommonName:              derived.CommonName,
		Fingerprint:             derived.Fingerprint,
		SubjectAlternativeNames: derived.SubjectAlternativeNames,
		ExpireTime:              derived.ExpireTime,
		EnterpriseProjectID:     ep,
		ProtectionStatus:        protStatus,
		ProtectionReason:        in.ProtectionReason,
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.certificates(t).Create(ctx, rec.ID, rec); err != nil {
		return certificate{}, err
	}
	return rec, nil
}

func (s *Service) certGet(ctx context.Context, t Tenant, id string) (certificate, error) {
	rec, err := s.certificates(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return certificate{}, errNotFound("certificate", id)
	}
	if err != nil {
		return certificate{}, err
	}
	return rec, nil
}

func (s *Service) certList(ctx context.Context, t Tenant, f certListFilter) ([]certificate, pageInfo, error) {
	items, err := s.certificates(t).List(ctx, func(c certificate) bool {
		if !matchesAny(f.IDs, c.ID) {
			return false
		}
		if !matchesAny(f.Names, c.Name) {
			return false
		}
		if !matchesAny(f.Descriptions, c.Description) {
			return false
		}
		if f.AdminStateUp != nil && c.AdminStateUp != *f.AdminStateUp {
			return false
		}
		if !matchesAny(f.Domains, c.Domain) {
			return false
		}
		if !matchesAny(f.Types, c.Type) {
			return false
		}
		if !matchesAny(f.ScmCertificateIDs, "") {
			return false
		}
		if !matchesAny(f.CommonNames, c.CommonName) {
			return false
		}
		if !matchesAny(f.Fingerprints, c.Fingerprint) {
			return false
		}
		if !matchesAny(f.Sources, "") {
			return false
		}
		protStatus := c.ProtectionStatus
		if protStatus == "" {
			protStatus = certDefaultProtectionStatus
		}
		if !matchesAny(f.ProtectionStatuses, protStatus) {
			return false
		}
		if !matchesAny(f.ProtectionReasons, c.ProtectionReason) {
			return false
		}
		ep := c.EnterpriseProjectID
		if ep == "" {
			ep = defaultEnterpriseProjectID
		}
		if !inEPList(f.EnterpriseProjectIDs, ep) {
			return false
		}
		return true
	})
	if err != nil {
		return nil, pageInfo{}, err
	}
	slices.SortFunc(items, func(a, b certificate) int {
		return strings.Compare(a.ID, b.ID)
	})
	return paginateSlice(items, func(c certificate) string { return c.ID }, f.Page)
}

func (s *Service) certUpdate(ctx context.Context, t Tenant, id string, in certUpdateInput) (certificate, error) {
	if in.EncCertificate != nil && *in.EncCertificate != "" {
		return certificate{}, errNotImplemented("enc_certificate")
	}
	if in.EncPrivateKey != nil && *in.EncPrivateKey != "" {
		return certificate{}, errNotImplemented("enc_private_key")
	}
	if in.ScmCertificateID != nil && *in.ScmCertificateID != "" {
		return certificate{}, errNotImplemented("scm_certificate_id")
	}
	if in.Source != nil {
		if *in.Source == "scm" {
			return certificate{}, errNotImplemented("scm")
		}
		if *in.Source != "" {
			return certificate{}, errInvalidInput("source")
		}
	}

	if in.Name != nil && !validName(*in.Name) {
		return certificate{}, errInvalidInput("name")
	}
	if in.Description != nil && !validDescription(*in.Description) {
		return certificate{}, errInvalidInput("description")
	}
	if in.ProtectionStatus != nil && !certValidProtectionStatus(*in.ProtectionStatus) {
		return certificate{}, errInvalidInput("protection_status")
	}
	if in.ProtectionReason != nil && !certValidProtectionReason(*in.ProtectionReason) {
		return certificate{}, errInvalidInput("protection_reason")
	}
	if in.Domain != nil && *in.Domain != "" && !certValidDomainList(*in.Domain) {
		return certificate{}, errInvalidInput("domain")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.certificates(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return certificate{}, errNotFound("certificate", id)
	}
	if err != nil {
		return certificate{}, err
	}

	if in.Domain != nil && *in.Domain == "" && rec.Domain != "" {
		used, err := s.certIsUsedByListener(ctx, t, id)
		if err != nil {
			return certificate{}, err
		}
		if used {
			return certificate{}, errConflict("The certificate is in use by a listener and its domain cannot be cleared.")
		}
	}

	if rec.Type == certTypeServer {
		switch {
		case in.Certificate != nil && in.PrivateKey != nil:
			derived, err := certValidateServerPair(*in.Certificate, *in.PrivateKey)
			if err != nil {
				return certificate{}, err
			}
			sealed, err := s.vault.Seal(*in.PrivateKey, certVaultLabelPrefix+rec.ID)
			if err != nil {
				return certificate{}, err
			}
			rec.Certificate = *in.Certificate
			rec.SealedPrivateKey = sealed
			rec.ExpireTime = derived.ExpireTime
			rec.CommonName = derived.CommonName
			rec.SubjectAlternativeNames = derived.SubjectAlternativeNames
			rec.Fingerprint = derived.Fingerprint
		case in.Certificate != nil:
			existingKey, err := s.vault.Open(rec.SealedPrivateKey, certVaultLabelPrefix+rec.ID)
			if err != nil {
				return certificate{}, errInvalidCertificate()
			}
			derived, err := certValidateServerPair(*in.Certificate, existingKey)
			if err != nil {
				return certificate{}, err
			}
			rec.Certificate = *in.Certificate
			rec.ExpireTime = derived.ExpireTime
			rec.CommonName = derived.CommonName
			rec.SubjectAlternativeNames = derived.SubjectAlternativeNames
			rec.Fingerprint = derived.Fingerprint
		case in.PrivateKey != nil:
			if _, err := certValidateServerPair(rec.Certificate, *in.PrivateKey); err != nil {
				return certificate{}, err
			}
			sealed, err := s.vault.Seal(*in.PrivateKey, certVaultLabelPrefix+rec.ID)
			if err != nil {
				return certificate{}, err
			}
			rec.SealedPrivateKey = sealed
		}
	} else if in.Certificate != nil {
		derived, err := certValidateCA(*in.Certificate)
		if err != nil {
			return certificate{}, err
		}
		rec.Certificate = *in.Certificate
		rec.ExpireTime = derived.ExpireTime
		rec.CommonName = derived.CommonName
		rec.SubjectAlternativeNames = derived.SubjectAlternativeNames
		rec.Fingerprint = derived.Fingerprint
	}

	if in.Name != nil {
		rec.Name = *in.Name
	}
	if in.Description != nil {
		rec.Description = *in.Description
	}
	if in.Domain != nil {
		rec.Domain = *in.Domain
	}
	if in.AdminStateUp != nil {
		rec.AdminStateUp = *in.AdminStateUp
	}
	if in.ProtectionStatus != nil {
		if *in.ProtectionStatus == "" {
			rec.ProtectionStatus = certDefaultProtectionStatus
		} else {
			rec.ProtectionStatus = *in.ProtectionStatus
		}
	}
	if in.ProtectionReason != nil {
		rec.ProtectionReason = *in.ProtectionReason
	}
	rec.UpdatedAt = s.nowUTC()

	if err := s.certificates(t).Put(ctx, rec.ID, rec); err != nil {
		return certificate{}, err
	}
	return rec, nil
}

func (s *Service) certDelete(ctx context.Context, t Tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.certificates(t).Get(ctx, id); errors.Is(err, store.ErrNotFound) {
		return errNotFound("certificate", id)
	} else if err != nil {
		return err
	}

	used, err := s.certIsUsedByListener(ctx, t, id)
	if err != nil {
		return err
	}
	if used {
		return errConflict("The certificate is in use by a listener.")
	}

	if err := s.certificates(t).Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
