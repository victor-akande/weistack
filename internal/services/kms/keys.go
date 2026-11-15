package kms

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
)

// Key states, as KMS reports them.
const (
	stateEnabled         = "2"
	stateDisabled        = "3"
	statePendingDeletion = "4"
)

// Limits, from the API reference and the documented quota.
const (
	maxKeysPerProject   = 100
	maxAlias            = 255
	maxDescription      = 255
	minPendingDays      = 7
	maxPendingDays      = 1096
	defaultRotationDays = 365
	minRotationDays     = 30
	maxRotationDays     = 365
	maxTags             = 20
	maxMaterials        = 1 << 16
)

// key is a customer master key.
type key struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	ProjectID   string `json:"project_id"`
	Region      string `json:"region"`
	Alias       string `json:"alias"`
	Description string `json:"description,omitempty"`
	Spec        string `json:"spec"`
	Usage       string `json:"usage"`
	Origin      string `json:"origin"`
	EP          string `json:"enterprise_project_id"`
	State       string `json:"state"`
	// Default marks a service's default key (<service>/default).
	Default    bool      `json:"default,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	DeletionAt time.Time `json:"deletion_at,omitzero"`

	Rotation         bool      `json:"rotation,omitempty"`
	RotationInterval int       `json:"rotation_interval"`
	LastRotation     time.Time `json:"last_rotation,omitzero"`
	// Materials are the key's material, oldest first, sealed by the
	// vault; rotation adds one, and ciphertexts name the one they used.
	Materials []material `json:"materials"`

	Tags []tag `json:"tags,omitempty"`
}

type material struct {
	Sealed    []byte    `json:"sealed"`
	CreatedAt time.Time `json:"created_at"`
}

type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

var (
	keyIDRE = regexp.MustCompile(`^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$`)
	// The alias's length (1 to 255) is checked apart: a counted
	// repetition compiles to a large program.
	aliasRE = regexp.MustCompile(`^[a-zA-Z0-9:/_-]+$`)
)

func validAlias(a string) bool {
	return len(a) >= 1 && len(a) <= maxAlias && aliasRE.MatchString(a) && !strings.HasSuffix(a, "/default")
}

// materialLabel binds a key's sealed material to the key and version.
func materialLabel(keyID string, version int) string {
	return "weistack:kms:" + keyID + ":" + strconv.Itoa(version)
}

// sealMaterial seals new material for k as its next version.
func (s *Service) addMaterial(k *key, raw []byte, at time.Time) error {
	sealed, err := s.vault.Seal(string(raw), materialLabel(k.ID, len(k.Materials)))
	if err != nil {
		return err
	}
	k.Materials = append(k.Materials, material{Sealed: sealed, CreatedAt: at})
	return nil
}

// material returns version v of k's material.
func (s *Service) material(k key, v int) ([]byte, error) {
	if v < 0 || v >= len(k.Materials) {
		return nil, errEnvelope
	}
	raw, err := s.vault.Open(k.Materials[v].Sealed, materialLabel(k.ID, v))
	if err != nil {
		return nil, fmt.Errorf("kms: opening the material of %s: %w", k.ID, err)
	}
	return []byte(raw), nil
}

// keyIDBytes is a key ID's 16 bytes, for envelopes; zero for a
// malformed ID.
func keyIDBytes(id string) (b [16]byte) {
	raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err == nil && len(raw) == 16 {
		copy(b[:], raw)
	}
	return b
}

func keyIDString(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// gone reports whether a key's scheduled deletion has come.
func (s *Service) gone(k key) bool {
	return k.State == statePendingDeletion && !s.now().Before(k.DeletionAt)
}

// find returns the key with that ID in t's project. A key of another
// project or account is not found, and nor is a deleted one.
func (s *Service) find(ctx context.Context, t tenant, id string) (key, error) {
	if !keyIDRE.MatchString(id) {
		return key{}, errKeyID
	}
	k, err := s.keys(t.Region).Get(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return key{}, errNoKey
	case err != nil:
		return key{}, err
	case k.AccountID != t.Account.ID || k.ProjectID != t.ProjectID:
		return key{}, errNoKey
	case s.gone(k):
		_ = s.keys(t.Region).Delete(ctx, id)
		return key{}, errNoKey
	}
	return k, nil
}

// update changes a key of t's project, found as find finds it.
func (s *Service) update(ctx context.Context, t tenant, id string, fn func(*key) error) (key, error) {
	if _, err := s.find(ctx, t, id); err != nil {
		return key{}, err
	}
	k, err := s.keys(t.Region).Update(ctx, id, fn)
	if errors.Is(err, store.ErrNotFound) {
		return key{}, errNoKey
	}
	return k, err
}

// projectKeys returns t's project's keys, oldest first, purging those
// whose deletion has come.
func (s *Service) projectKeys(ctx context.Context, t tenant) ([]key, error) {
	all, err := s.keys(t.Region).List(ctx, func(k key) bool {
		return k.AccountID == t.Account.ID && k.ProjectID == t.ProjectID
	})
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, k := range all {
		if s.gone(k) {
			_ = s.keys(t.Region).Delete(ctx, k.ID)
			continue
		}
		out = append(out, k)
	}
	slices.SortStableFunc(out, func(a, b key) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

// newKey is what create-key asks for.
type newKey struct {
	Alias, Description, Spec, Usage, Origin, EP string
	Default                                     bool
}

// createKey makes a key in t's project.
func (s *Service) createKey(ctx context.Context, t tenant, n newKey) (key, error) {
	switch {
	case !n.Default && !validAlias(n.Alias):
		return key{}, errAlias
	case len(n.Description) > maxDescription:
		return key{}, errDescription
	}
	if n.Spec == "" {
		n.Spec = specAES256
	}
	if _, ok := specs[n.Spec]; !ok {
		return key{}, errParam
	}
	if n.Usage == "" {
		n.Usage = defaultUsage(n.Spec)
	}
	if !usageAllowed(n.Spec, n.Usage) {
		return key{}, errParam
	}
	switch n.Origin {
	case "", "kms":
		n.Origin = "kms"
	default:
		// Importing key material is not emulated.
		return key{}, errParam
	}
	if n.EP == "" {
		n.EP = "0"
	}
	raw, err := generate(n.Spec)
	if err != nil {
		return key{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	k := key{
		ID: s.ids.UUID(), AccountID: t.Account.ID, ProjectID: t.ProjectID, Region: t.Region,
		Alias: n.Alias, Description: n.Description, Spec: n.Spec, Usage: n.Usage, Origin: n.Origin, EP: n.EP,
		State: stateEnabled, Default: n.Default, CreatedAt: now, RotationInterval: defaultRotationDays,
	}
	if err := s.addMaterial(&k, raw, now); err != nil {
		return key{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.projectKeys(ctx, t)
	if err != nil {
		return key{}, err
	}
	custom := 0
	for _, e := range existing {
		if e.Alias == n.Alias {
			return key{}, errDuplicateAlias
		}
		if !e.Default {
			custom++
		}
	}
	if !n.Default && custom >= maxKeysPerProject {
		return key{}, errTooManyKeys
	}
	if err := s.keys(t.Region).Create(ctx, k.ID, k); err != nil {
		return key{}, err
	}
	s.log.InfoContext(ctx, "kms key created", "key_id", k.ID, "alias", k.Alias, "spec", k.Spec)
	return k, nil
}

// DefaultKey returns the default key of a service (alias
// <service>/default) in a project of an account, creating it on first
// use as Huawei Cloud does.
func (s *Service) defaultKey(ctx context.Context, t tenant, service string) (key, error) {
	alias := service + "/default"
	keys, err := s.projectKeys(ctx, t)
	if err != nil {
		return key{}, err
	}
	for _, k := range keys {
		if k.Default && k.Alias == alias {
			return k, nil
		}
	}
	k, err := s.createKey(ctx, t, newKey{Alias: alias, Default: true, Description: "Default key of " + service})
	if errors.Is(err, errDuplicateAlias) {
		// Made by a concurrent request.
		return s.defaultKey(ctx, t, service)
	}
	return k, err
}

// usable checks that a key can be used for cryptography.
func usable(k key) error {
	switch k.State {
	case stateEnabled:
		return nil
	case stateDisabled:
		return errDisabled
	case statePendingDeletion:
		return errPendingDeletion
	}
	return errNotEnabled
}

// rotateIfDue gives a key with rotation enabled new material once its
// interval has passed since the last rotation (or its creation).
func (s *Service) rotateIfDue(ctx context.Context, t tenant, k key) (key, error) {
	if !k.Rotation {
		return k, nil
	}
	last := k.LastRotation
	if last.IsZero() {
		last = k.CreatedAt
	}
	now := s.now().UTC()
	if now.Before(last.AddDate(0, 0, k.RotationInterval)) {
		return k, nil
	}
	return s.rotate(ctx, t, k.ID, now)
}

// rotate gives a key new material.
func (s *Service) rotate(ctx context.Context, t tenant, id string, now time.Time) (key, error) {
	cur, err := s.find(ctx, t, id)
	if err != nil {
		return key{}, err
	}
	if len(cur.Materials) >= maxMaterials {
		return cur, nil // envelopes number material in 16 bits
	}
	raw, err := generate(cur.Spec)
	if err != nil {
		return key{}, err
	}
	return s.update(ctx, t, id, func(k *key) error {
		if err := s.addMaterial(k, raw, now); err != nil {
			return err
		}
		k.LastRotation = now
		return nil
	})
}
