package wiretime

import (
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 12, 7, 5, 9, 123456789, time.FixedZone("WAT", 3600))
	for _, zulu := range []bool{false, true} {
		got := string(AppendQuoted(nil, at, zulu))
		want := `"2026-11-12T06:05:09"`
		if zulu {
			want = `"2026-11-12T06:05:09Z"`
		}
		if got != want {
			t.Errorf("AppendQuoted(zulu=%v) = %s, want %s", zulu, got, want)
		}
		back, err := ParseQuoted([]byte(got), zulu)
		if err != nil || !back.Equal(at.Truncate(time.Second)) || back.Location() != time.UTC {
			t.Errorf("ParseQuoted(%s) = %v, %v", got, back, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		``, `""`, `"2026-11-12T06:05:09`, `2026-11-12T06:05:09"`, `"2026-11-12 06:05:09"`, `"2026-13-12T06:05:09"`,
		`"2026-00-12T06:05:09"`, `"2026-04-31T06:05:09"`, `"2025-02-29T06:05:09"`, `"2026-11-12T24:00:00"`,
		`"2026-11-12T06:60:09"`, `"2026-11-12T06:05:60"`, `"2026-1a-12T06:05:09"`, `"2026-11-12T06:05:09Z"`, `null`,
	} {
		if _, err := ParseQuoted([]byte(in), false); err == nil {
			t.Errorf("ParseQuoted(%s) accepted it", in)
		}
	}
	if _, err := ParseQuoted([]byte(`"2026-11-12T06:05:09"`), true); err == nil {
		t.Error("the Z layout accepted a value without Z")
	}
	if _, err := ParseQuoted([]byte(`"2024-02-29T00:00:00"`), false); err != nil {
		t.Errorf("a leap day: %v", err)
	}
}

func TestYearsOutsideFourDigits(t *testing.T) {
	t.Parallel()
	far := time.Date(12026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got, want := string(AppendQuoted(nil, far, true)), `"`+far.Format(LayoutZ)+`"`; got != want {
		t.Errorf("year 12026: %s, want %s", got, want)
	}
}

// FuzzParse holds ParseQuoted to time.ParseInLocation: whatever it
// accepts, time.Parse accepts as the same instant, and it accepts every
// canonical timestamp. It is stricter only about spellings time.Parse
// tolerates, such as a one-digit hour.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"2026-11-12T06:05:09", "2024-02-29T23:59:59Z", "0000-01-01T00:00:00", "2026-04-31T00:00:00", "9999-12-31T23:59:59Z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, zulu := range []bool{false, true} {
			layout := Layout
			if zulu {
				layout = LayoutZ
			}
			want, wantErr := time.ParseInLocation(layout, s, time.UTC)
			got, err := ParseQuoted([]byte(`"`+s+`"`), zulu)
			switch {
			case err == nil && wantErr != nil:
				t.Fatalf("%q (zulu=%v): accepted what time.Parse rejects: %v", s, zulu, wantErr)
			case err == nil && !got.Equal(want):
				t.Fatalf("%q: %v, want %v", s, got, want)
			case err != nil && wantErr == nil && want.Format(layout) == s:
				// time.Parse is lenient (it takes "T0:00:00" for "15:04:05");
				// rejecting a non-canonical spelling is fine, a canonical one
				// is not.
				t.Fatalf("%q (zulu=%v): rejected a canonical timestamp: %v", s, zulu, err)
			}
		}
	})
}

// FuzzAppend holds AppendQuoted to time.Format.
func FuzzAppend(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(1794400000))
	f.Add(int64(-62135596800))
	f.Fuzz(func(t *testing.T, sec int64) {
		at := time.Unix(sec, 0)
		for _, zulu := range []bool{false, true} {
			layout := Layout
			if zulu {
				layout = LayoutZ
			}
			if got, want := string(AppendQuoted(nil, at, zulu)), `"`+at.UTC().Format(layout)+`"`; got != want {
				t.Fatalf("%d: %s, want %s", sec, got, want)
			}
		}
	})
}

func BenchmarkParse(b *testing.B) {
	in := []byte(`"2026-11-12T06:05:09Z"`)
	b.Run("wiretime", func(b *testing.B) {
		for b.Loop() {
			_, _ = ParseQuoted(in, true)
		}
	})
	b.Run("time.Parse", func(b *testing.B) {
		for b.Loop() {
			_, _ = time.ParseInLocation(LayoutZ, string(in[1:len(in)-1]), time.UTC)
		}
	})
}
