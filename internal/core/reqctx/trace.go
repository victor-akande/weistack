package reqctx

import "strings"

// TraceParent is the W3C Trace Context request header.
const TraceParent = "traceparent"

// TraceResponse is the W3C Trace Context Level 2 response header that
// tells the caller which trace and span served its request.
const TraceResponse = "traceresponse"

// ParseTraceParent reads a version 00 traceparent header,
// "00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>". It reports
// false for anything else, including all-zero IDs, and the request then
// starts a new trace, as the specification says.
func ParseTraceParent(h string) (traceID, parentID, flags string, ok bool) {
	h = strings.TrimSpace(h)
	parts := strings.Split(h, "-")
	if len(parts) != 4 || parts[0] != "00" {
		return "", "", "", false
	}
	traceID, parentID, flags = parts[1], parts[2], parts[3]
	if !lowerHex(traceID, 32) || !lowerHex(parentID, 16) || !lowerHex(flags, 2) {
		return "", "", "", false
	}
	if strings.Trim(traceID, "0") == "" || strings.Trim(parentID, "0") == "" {
		return "", "", "", false
	}
	return traceID, parentID, flags, true
}

// FormatTraceResponse is the traceresponse value for info.
func FormatTraceResponse(info *Info) string {
	flags := info.TraceFlags
	if flags == "" {
		flags = "00"
	}
	return "00-" + info.TraceID + "-" + info.SpanID + "-" + flags
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
