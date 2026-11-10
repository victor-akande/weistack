package ims

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/victor-akande/weistack/internal/core/store"
)

// sortKeys are the accepted values of sort_key.
var sortKeys = map[string]func(a, b Image) int{
	"name":             func(a, b Image) int { return cmp.Compare(a.Name, b.Name) },
	"container_format": func(a, b Image) int { return cmp.Compare(a.ContainerFormat, b.ContainerFormat) },
	"disk_format":      func(a, b Image) int { return cmp.Compare(a.DiskFormat, b.DiskFormat) },
	"status":           func(a, b Image) int { return cmp.Compare(a.Status, b.Status) },
	"id":               func(a, b Image) int { return cmp.Compare(a.ID, b.ID) },
	"size":             func(a, b Image) int { return cmp.Compare(a.Size, b.Size) },
	"created_at": func(a, b Image) int {
		return time.Time(a.CreatedAt).Compare(time.Time(b.CreatedAt))
	},
}

const (
	defaultSortKey = "created_at"
	defaultSortDir = "desc"
)

// visible returns every image the tenant can see: the region's public
// images and the tenant's own.
func (s *Service) visible(ctx context.Context, t Tenant) ([]Image, error) {
	if err := s.ensureSeeded(ctx, t.Region); err != nil {
		return nil, err
	}
	public, err := s.publicImages(t.Region).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	private, err := s.privateImages(t).List(ctx, nil)
	if err != nil {
		return nil, err
	}
	return append(public, private...), nil
}

// ListImages returns the images visible to the tenant that match f,
// sorted as f asks (newest first by default).
func (s *Service) ListImages(ctx context.Context, t Tenant, f ListImagesFilter) ([]Image, error) {
	key, dir := f.SortKey, f.SortDir
	if key == "" {
		key = defaultSortKey
	}
	if dir == "" {
		dir = defaultSortDir
	}
	compare, ok := sortKeys[key]
	if !ok {
		return nil, errInvalidRequest("sort_key %q is not supported", f.SortKey)
	}
	if dir != "asc" && dir != "desc" {
		return nil, errInvalidRequest("sort_dir must be asc or desc")
	}

	all, err := s.visible(ctx, t)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, img := range all {
		if f.matches(img) {
			out = append(out, img)
		}
	}
	slices.SortStableFunc(out, func(a, b Image) int {
		c := compare(a, b)
		if c == 0 {
			c = cmp.Compare(a.ID, b.ID) // a total order keeps paging stable
		}
		if dir == "desc" {
			c = -c
		}
		return c
	})
	return out, nil
}

func (f ListImagesFilter) matches(img Image) bool {
	eq := func(want, got string) bool { return want == "" || want == got }
	return eq(f.ImageType, img.ImageType) &&
		eq(f.Visibility, img.Visibility) &&
		eq(f.ID, img.ID) &&
		eq(f.Name, img.Name) &&
		eq(f.Status, img.Status) &&
		eq(f.Platform, img.Platform) &&
		eq(f.OSType, img.OSType) &&
		eq(f.OSBit, img.OSBit) &&
		eq(f.Owner, img.Owner) &&
		eq(f.DiskFormat, img.DiskFormat) &&
		eq(f.ContainerFormat, img.ContainerFormat) &&
		eq(f.VirtualEnvType, img.VirtualEnvType) &&
		(f.Tag == "" || slices.Contains(img.Tags, f.Tag)) &&
		(f.Protected == nil || *f.Protected == img.Protected)
}

// GetImage returns one image visible to the tenant.
func (s *Service) GetImage(ctx context.Context, t Tenant, id string) (Image, error) {
	if err := s.ensureSeeded(ctx, t.Region); err != nil {
		return Image{}, err
	}
	img, err := s.privateImages(t).Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		img, err = s.publicImages(t.Region).Get(ctx, id)
	}
	if errors.Is(err, store.ErrNotFound) {
		return Image{}, errImageNotFound(id)
	}
	return img, err
}
