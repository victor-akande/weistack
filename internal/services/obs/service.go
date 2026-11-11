// Package obs emulates Huawei Cloud Object Storage Service.
//
// OBS is S3-compatible with its own dialect: "x-obs-" headers instead of
// "x-amz-", an "OBS" authorization scheme and its own XML namespace.
// Both dialects are served, chosen per request, because Huawei's SDKs
// use either depending on configuration and plain S3 tools are common.
//
// Bucket and object metadata live in the store; object bodies are files
// under a data directory and are always streamed, never held in memory.
package obs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/store"
)

// Buckets share one namespace across every region and account, so their
// records are not scoped by region or project.
const (
	globalRegion = "_"
	kindBucket   = "obs.bucket"
)

// Deps are the dependencies of the service.
type Deps struct {
	Store  store.Store
	IDs    *ids.Generator
	Logger *slog.Logger
	// DataDir is where object bodies are kept. It is created if missing.
	DataDir string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Service is the OBS emulator.
type Service struct {
	store store.Store
	ids   *ids.Generator
	log   *slog.Logger
	now   func() time.Time
	blobs *blobStore

	// mu serialises bucket creation and deletion, which check then write.
	mu sync.Mutex
}

// New returns the OBS service.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.IDs == nil || d.Logger == nil || d.DataDir == "" {
		return nil, errors.New("obs: Store, IDs, Logger and DataDir are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	blobs, err := newBlobStore(d.DataDir)
	if err != nil {
		return nil, err
	}
	return &Service{store: d.Store, ids: d.IDs, log: d.Logger, now: d.Now, blobs: blobs}, nil
}

// Name implements server.Service.
func (s *Service) Name() string { return "obs" }

// Version implements server.Service.
func (s *Service) Version() string { return "S3-compatible" }

// MaxBodyBytes implements server.BodyLimiter: uploads are unlimited and
// streamed to disk.
func (s *Service) MaxBodyBytes() int64 { return 0 }

// Reset implements server.Resetter: when the store is wiped, the object
// bodies go too.
func (s *Service) Reset(context.Context) error {
	return s.blobs.reset()
}

func (s *Service) buckets() store.Collection[Bucket] {
	return store.Of[Bucket](s.store, store.Scope{Region: globalRegion, ProjectID: store.Global, Kind: kindBucket})
}
