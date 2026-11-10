package pagination

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
)

var limits = Limits{Default: 3, Min: 0, Max: 5}

func ident(s string) string { return s }

func TestParseMarker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		query   string
		want    Marker
		wantErr error
	}{
		{"", Marker{Limit: 3}, nil},
		{"marker=b&limit=2", Marker{ID: "b", Limit: 2}, nil},
		{"limit=0", Marker{Limit: 0}, nil},
		{"limit=5", Marker{Limit: 5}, nil},
		{"limit=6", Marker{}, ErrInvalidLimit},
		{"limit=-1", Marker{}, ErrInvalidLimit},
		{"limit=ten", Marker{}, ErrInvalidLimit},
	}
	for _, tt := range tests {
		q, _ := url.ParseQuery(tt.query)
		got, err := ParseMarker(q, limits)
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%q: err = %v, want %v", tt.query, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("%q: got %+v, want %+v", tt.query, got, tt.want)
		}
	}
}

func TestByMarker(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c", "d"}
	tests := []struct {
		name    string
		m       Marker
		want    []string
		wantErr error
	}{
		{"first page", Marker{Limit: 2}, []string{"a", "b"}, nil},
		{"after marker", Marker{ID: "b", Limit: 2}, []string{"c", "d"}, nil},
		{"short last page", Marker{ID: "c", Limit: 2}, []string{"d"}, nil},
		{"marker is last item", Marker{ID: "d", Limit: 2}, []string{}, nil},
		{"zero limit", Marker{Limit: 0}, []string{}, nil},
		{"limit beyond length", Marker{Limit: 99}, items, nil},
		{"unknown marker", Marker{ID: "zzz", Limit: 2}, nil, ErrMarkerNotFound},
	}
	for _, tt := range tests {
		got, err := ByMarker(items, ident, tt.m)
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
		if len(got) != len(tt.want) || (len(got) > 0 && !reflect.DeepEqual(got, tt.want)) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParseOffset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		query   string
		want    Offset
		wantErr error
	}{
		{"", Offset{Limit: 3}, nil},
		{"offset=2&limit=1", Offset{Offset: 2, Limit: 1}, nil},
		{"offset=-1", Offset{}, ErrInvalidOffset},
		{"offset=x", Offset{}, ErrInvalidOffset},
		{"offset=1&limit=9", Offset{}, ErrInvalidLimit},
	}
	for _, tt := range tests {
		q, _ := url.ParseQuery(tt.query)
		got, err := ParseOffset(q, limits)
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%q: err = %v, want %v", tt.query, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("%q: got %+v, want %+v", tt.query, got, tt.want)
		}
	}
}

func TestByOffset(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c", "d"}
	tests := []struct {
		name string
		o    Offset
		want []string
	}{
		{"start", Offset{Offset: 0, Limit: 2}, []string{"a", "b"}},
		{"middle", Offset{Offset: 1, Limit: 2}, []string{"b", "c"}},
		{"short tail", Offset{Offset: 3, Limit: 2}, []string{"d"}},
		{"at end", Offset{Offset: 4, Limit: 2}, []string{}},
		{"past end", Offset{Offset: 40, Limit: 2}, []string{}},
		{"zero limit", Offset{Offset: 1, Limit: 0}, []string{}},
	}
	for _, tt := range tests {
		got := ByOffset(items, tt.o)
		if len(got) != len(tt.want) || (len(got) > 0 && !reflect.DeepEqual(got, tt.want)) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// A page must not let append() scribble over the caller's backing array.
func TestPagesDoNotShareCapacity(t *testing.T) {
	t.Parallel()

	items := []string{"a", "b", "c", "d"}
	page := ByOffset(items, Offset{Offset: 0, Limit: 2})
	_ = append(page, "X")
	if items[2] != "c" {
		t.Fatalf("append to a page overwrote the source slice: %v", items)
	}
}

func FuzzParseOffset(f *testing.F) {
	f.Add("offset=1&limit=2")
	f.Add("limit=-9999999999999999999")
	f.Add("offset=%zz")
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		o, err := ParseOffset(q, limits)
		if err != nil {
			return
		}
		if o.Offset < 0 || o.Limit < limits.Min || o.Limit > limits.Max {
			t.Fatalf("accepted out-of-range values: %+v", o)
		}
		_ = ByOffset([]int{1, 2, 3}, o)
	})
}
