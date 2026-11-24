package reqctx

import "testing"

func TestParseTraceParent(t *testing.T) {
	t.Parallel()

	const trace, parent = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	for _, tc := range []struct {
		name, header string
		ok           bool
	}{
		{"valid, sampled", "00-" + trace + "-" + parent + "-01", true},
		{"valid, not sampled", "00-" + trace + "-" + parent + "-00", true},
		{"surrounding spaces", "  00-" + trace + "-" + parent + "-01 ", true},
		{"empty", "", false},
		{"unknown version", "01-" + trace + "-" + parent + "-01", false},
		{"forbidden version ff", "ff-" + trace + "-" + parent + "-01", false},
		{"upper-case hex", "00-4BF92F3577B34DA6A3CE929D0E0E4736-" + parent + "-01", false},
		{"short trace", "00-4bf92f3577b34da6-" + parent + "-01", false},
		{"short parent", "00-" + trace + "-00f067aa-01", false},
		{"all-zero trace", "00-00000000000000000000000000000000-" + parent + "-01", false},
		{"all-zero parent", "00-" + trace + "-0000000000000000-01", false},
		{"not hex", "00-" + trace + "-" + parent + "-zz", false},
		{"extra field", "00-" + trace + "-" + parent + "-01-x", false},
	} {
		gotTrace, gotParent, gotFlags, ok := ParseTraceParent(tc.header)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if ok && (gotTrace != trace || gotParent != parent || len(gotFlags) != 2) {
			t.Errorf("%s: got %q %q %q", tc.name, gotTrace, gotParent, gotFlags)
		}
	}
}

func TestFormatTraceResponse(t *testing.T) {
	t.Parallel()

	info := &Info{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "b7ad6b7169203331", TraceFlags: "01"}
	if got, want := FormatTraceResponse(info), "00-4bf92f3577b34da6a3ce929d0e0e4736-b7ad6b7169203331-01"; got != want {
		t.Errorf("traceresponse = %q, want %q", got, want)
	}
	info.TraceFlags = ""
	if got := FormatTraceResponse(info); got[len(got)-3:] != "-00" {
		t.Errorf("traceresponse without flags = %q, want flags 00", got)
	}
}
