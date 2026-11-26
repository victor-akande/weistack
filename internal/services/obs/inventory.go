package obs

import (
	"context"
	"strings"

	"github.com/victor-akande/weistack/internal/core/auth"
	"github.com/victor-akande/weistack/internal/core/inventory"
	"github.com/victor-akande/weistack/internal/core/store"
)

// ReportResources implements inventory.Reporter: buckets only. Objects and
// multipart uploads in progress are not standalone Config resources and are
// not reported.
func (s *Service) ReportResources(ctx context.Context, emit func(inventory.Resource) error) error {
	return inventory.Each(ctx, s.store, kindBucket, func(_ store.Scope, b Bucket) error {
		return emit(s.bucketResource(b))
	})
}

func (s *Service) bucketResource(b Bucket) inventory.Resource {
	return inventory.Resource{
		Type:      inventory.OBSBuckets,
		ID:        b.Name,
		Name:      b.Name,
		AccountID: s.bucketAccount(b.Owner),
		RegionID:  b.Region,
		Created:   b.Created,
		State:     inventory.Succeeded,
	}
}

// bucketAccount resolves a bucket owner to its account ID. Requests resolved
// by auth.Middleware store "domain:<accountID>"; buckets created with a raw
// access key (before the key was registered or without server middleware)
// look the key up through AccountOf.
func (s *Service) bucketAccount(owner string) string {
	if s.accountOf == nil || owner == "" {
		return ""
	}
	if account, ok := strings.CutPrefix(owner, auth.AccountOwnerPrefix); ok {
		return account
	}
	if account, ok := s.accountOf(owner); ok {
		return account
	}
	return ""
}
