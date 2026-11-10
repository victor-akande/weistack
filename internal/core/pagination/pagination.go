// Package pagination implements the two paging styles of Huawei Cloud list
// APIs: marker+limit (VPC, IMS) and offset+limit (ECS, RDS).
//
// The helpers return plain Go errors; each service maps them to its own
// error code.
package pagination

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// Errors returned by the parsers and pagers.
var (
	ErrInvalidLimit   = errors.New("pagination: invalid limit")
	ErrInvalidOffset  = errors.New("pagination: invalid offset")
	ErrMarkerNotFound = errors.New("pagination: marker not found")
)

// Limits bounds the "limit" query parameter of one operation.
type Limits struct {
	// Default applies when the client sends no limit.
	Default int
	// Min and Max are the inclusive bounds of an explicit limit.
	Min, Max int
}

func (l Limits) parse(q url.Values) (int, error) {
	raw := q.Get("limit")
	if raw == "" {
		return l.Default, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not an integer", ErrInvalidLimit, raw)
	}
	if n < l.Min || n > l.Max {
		return 0, fmt.Errorf("%w: %d is outside %d-%d", ErrInvalidLimit, n, l.Min, l.Max)
	}
	return n, nil
}

// Marker is a parsed marker+limit request. An empty ID starts from the
// beginning; otherwise the page starts after the item with that ID.
type Marker struct {
	ID    string
	Limit int
}

// ParseMarker reads "marker" and "limit" from a query string.
func ParseMarker(q url.Values, limits Limits) (Marker, error) {
	limit, err := limits.parse(q)
	if err != nil {
		return Marker{}, err
	}
	return Marker{ID: q.Get("marker"), Limit: limit}, nil
}

// ByMarker returns the page of items that follows the marker. id extracts
// an item's ID. The result aliases items; it is not a copy.
func ByMarker[T any](items []T, id func(T) string, m Marker) ([]T, error) {
	start := 0
	if m.ID != "" {
		start = -1
		for i, item := range items {
			if id(item) == m.ID {
				start = i + 1
				break
			}
		}
		if start < 0 {
			return nil, fmt.Errorf("%w: %q", ErrMarkerNotFound, m.ID)
		}
	}
	return window(items, start, m.Limit), nil
}

// Offset is a parsed offset+limit request. Offset is a zero-based item
// index. Operations whose "offset" is a page number (some ECS lists)
// convert before calling ByOffset.
type Offset struct {
	Offset int
	Limit  int
}

// ParseOffset reads "offset" and "limit" from a query string.
func ParseOffset(q url.Values, limits Limits) (Offset, error) {
	limit, err := limits.parse(q)
	if err != nil {
		return Offset{}, err
	}
	offset := 0
	if raw := q.Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil {
			return Offset{}, fmt.Errorf("%w: %q is not an integer", ErrInvalidOffset, raw)
		}
		if offset < 0 {
			return Offset{}, fmt.Errorf("%w: %d is negative", ErrInvalidOffset, offset)
		}
	}
	return Offset{Offset: offset, Limit: limit}, nil
}

// ByOffset returns the requested window of items. An offset past the end
// yields an empty page. The result aliases items; it is not a copy.
func ByOffset[T any](items []T, o Offset) []T {
	return window(items, o.Offset, o.Limit)
}

func window[T any](items []T, start, limit int) []T {
	if start >= len(items) || limit <= 0 {
		return items[:0:0]
	}
	end := len(items)
	if limit < end-start {
		end = start + limit
	}
	return items[start:end:end]
}
