package kms

import (
	"context"
	"errors"
	"strings"

	"github.com/victor-akande/weistack/internal/core/cmk"
)

// KMS for the services that encrypt with it (cmk.Keys): OBS's SSE-KMS,
// encrypted disks and encrypted RDS storage. They name a key by ID, or
// by OBS's <region>:<account-id>:key/<key-id>, or name none for their
// default key.

var _ cmk.Keys = (*Service)(nil)

// projectOf is an account's project in region: the configured one for
// the primary account in the default region, a derived one otherwise.
func (s *Service) projectOf(ctx context.Context, region string) tenant {
	a := s.account(ctx)
	project := a.DerivedProjectID(region)
	if s.dir.Primary(a) && region == s.defaultRegion && s.defaultProject != "" {
		project = s.defaultProject
	}
	return tenant{Region: region, ProjectID: project, Account: a}
}

// bareKeyID takes the key ID out of OBS's longer form.
func bareKeyID(id string) string {
	if _, after, ok := strings.Cut(id, ":key/"); ok {
		return after
	}
	return id
}

// usableKey finds a key a service may encrypt with: its default key when
// none is named.
func (s *Service) usableKey(ctx context.Context, t tenant, keyID, service string) (key, error) {
	var (
		k   key
		err error
	)
	if keyID == "" {
		k, err = s.defaultKey(ctx, t, service)
	} else {
		k, err = s.find(ctx, t, bareKeyID(keyID))
	}
	switch {
	case errors.Is(err, errNoKey), errors.Is(err, errKeyID):
		return key{}, cmk.ErrNotFound
	case err != nil:
		return key{}, err
	case specs[k.Spec] != symmetric || k.Usage != usageEncrypt:
		return key{}, cmk.ErrNotFound
	case usable(k) != nil:
		return key{}, cmk.ErrDisabled
	}
	return k, nil
}

// Check implements cmk.Keys.
func (s *Service) Check(ctx context.Context, region, projectID, keyID, service string) (string, error) {
	t := tenant{Region: region, ProjectID: projectID, Account: s.account(ctx)}
	k, err := s.usableKey(ctx, t, keyID, service)
	return k.ID, err
}

// NewDataKey implements cmk.Keys.
func (s *Service) NewDataKey(ctx context.Context, region, keyID, service string) (cmk.DataKey, error) {
	t := s.projectOf(ctx, region)
	k, err := s.usableKey(ctx, t, keyID, service)
	if err != nil {
		return cmk.DataKey{}, err
	}
	k, err = s.rotateIfDue(ctx, t, k)
	if err != nil {
		return cmk.DataKey{}, err
	}
	m, err := s.material(k, len(k.Materials)-1)
	if err != nil {
		return cmk.DataKey{}, err
	}
	plain, err := random(32)
	if err != nil {
		return cmk.DataKey{}, err
	}
	sealed, err := seal(k.Spec, m, envelopeHeader(k), plain, nil)
	if err != nil {
		return cmk.DataKey{}, err
	}
	return cmk.DataKey{KeyID: k.ID, KeyURN: region + ":" + k.AccountID + ":key/" + k.ID, Plain: plain, Sealed: sealed}, nil
}

// OpenDataKey implements cmk.Keys.
func (s *Service) OpenDataKey(ctx context.Context, region string, sealed []byte) ([]byte, error) {
	h, err := parseHeader(sealed)
	if err != nil {
		return nil, cmk.ErrNotFound
	}
	k, err := s.keys(region).Get(ctx, keyIDString(h.key))
	if err != nil || s.gone(k) {
		return nil, cmk.ErrNotFound
	}
	if usable(k) != nil {
		return nil, cmk.ErrDisabled
	}
	m, err := s.material(k, int(h.material))
	if err != nil {
		return nil, cmk.ErrNotFound
	}
	return open(k.Spec, m, sealed, nil)
}

// ResolveAlias implements cmk.Keys.
func (s *Service) ResolveAlias(ctx context.Context, region, alias string) (string, error) {
	if alias == "" {
		return "", cmk.ErrNotFound
	}
	t := s.projectOf(ctx, region)
	keys, err := s.projectKeys(ctx, t)
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		if k.Alias == alias {
			return k.ID, nil
		}
	}
	return "", cmk.ErrNotFound
}
