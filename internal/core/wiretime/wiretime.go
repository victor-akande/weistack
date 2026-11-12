// Package wiretime encodes and decodes the fixed timestamp formats of
// Huawei Cloud APIs, "2006-01-02T15:04:05" and "2006-01-02T15:04:05Z",
// as JSON strings.
//
// It exists for speed: every stored record carries timestamps, and a list
// of a thousand resources decodes and encodes thousands of them. The
// general time.Parse and time.Format spent most of that time interpreting
// the layout; these functions do only what the fixed layouts need, and
// fuzzing holds them to the same results.
package wiretime

import (
	"errors"
	"time"
)

const (
	// Layout is the zone-less format, in UTC by convention.
	Layout = "2006-01-02T15:04:05"
	// LayoutZ is the same with an explicit UTC designator.
	LayoutZ = "2006-01-02T15:04:05Z"
)

// ErrSyntax reports a value that is not a quoted timestamp of the layout.
var ErrSyntax = errors.New("wiretime: not a quoted timestamp of the expected layout")

// AppendQuoted appends t in UTC, second resolution, as a JSON string:
// in LayoutZ when zulu, else in Layout.
func AppendQuoted(b []byte, t time.Time, zulu bool) []byte {
	t = t.UTC()
	year, month, day := t.Date()
	hour, minute, second := t.Clock()
	if year < 0 || year > 9999 {
		// Outside four digits the general formatter decides.
		layout := Layout
		if zulu {
			layout = LayoutZ
		}
		b = append(b, '"')
		b = t.AppendFormat(b, layout)
		return append(b, '"')
	}
	b = append(b, '"')
	b = appendInt(b, year, 4)
	b = append(b, '-')
	b = appendInt(b, int(month), 2)
	b = append(b, '-')
	b = appendInt(b, day, 2)
	b = append(b, 'T')
	b = appendInt(b, hour, 2)
	b = append(b, ':')
	b = appendInt(b, minute, 2)
	b = append(b, ':')
	b = appendInt(b, second, 2)
	if zulu {
		b = append(b, 'Z')
	}
	return append(b, '"')
}

func appendInt(b []byte, v, width int) []byte {
	var buf [4]byte
	for i := width - 1; i >= 0; i-- {
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(b, buf[:width]...)
}

// ParseQuoted parses a JSON string in LayoutZ when zulu, else in Layout,
// as a UTC time.
func ParseQuoted(b []byte, zulu bool) (time.Time, error) {
	want := len(Layout) + 2
	if zulu {
		want++
	}
	if len(b) != want || b[0] != '"' || b[len(b)-1] != '"' {
		return time.Time{}, ErrSyntax
	}
	s := b[1 : len(b)-1]
	if s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || zulu && s[19] != 'Z' {
		return time.Time{}, ErrSyntax
	}
	year, ok1 := digits(s[0:4])
	month, ok2 := digits(s[5:7])
	day, ok3 := digits(s[8:10])
	hour, ok4 := digits(s[11:13])
	minute, ok5 := digits(s[14:16])
	second, ok6 := digits(s[17:19])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 ||
		month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, ErrSyntax
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if t.Day() != day { // 31 April, 29 February of a common year
		return time.Time{}, ErrSyntax
	}
	return t, nil
}

func digits(b []byte) (int, bool) {
	v := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, true
}
