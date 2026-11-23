// Package quota holds the per-project limits of the emulated services:
// how many VPCs, volumes, load balancers and so on one project may hold.
//
// The defaults are those of a new Huawei Cloud account (defaults.go says
// where each comes from), and every limit can be changed with -quotas.
// Services count their records and ask Allows before creating; records
// already over a limit are kept, only new creates are refused.
package quota

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Unlimited is a limit that is never reached, as in Huawei's quota APIs.
const Unlimited = -1

// Key names a limit. Every key is listed in defaults.go.
type Key string

// Limits are the effective limits. The zero value uses the defaults.
// Limits are read-only once built and safe for concurrent use.
type Limits struct {
	set map[Key]int // limits that differ from the defaults
}

// Get returns the limit for k, or Unlimited. It panics on a key that is
// not in the table, so a typo fails every test that reaches it.
func (l Limits) Get(k Key) int {
	d, ok := defaults[k]
	if !ok {
		panic(fmt.Sprintf("quota: unknown key %q", k))
	}
	if v, ok := l.set[k]; ok {
		return v
	}
	return d.value
}

// Allows reports whether a project that holds used of k may add want
// more. Adding nothing is always allowed, even over the limit.
func (l Limits) Allows(k Key, used, want int) bool {
	limit := l.Get(k)
	return want <= 0 || limit == Unlimited || used+want <= limit
}

// With returns a copy of l with k set to v. It panics on an unknown key
// or a value below Unlimited.
func (l Limits) With(k Key, v int) Limits {
	if _, ok := defaults[k]; !ok {
		panic(fmt.Sprintf("quota: unknown key %q", k))
	}
	if v < Unlimited {
		panic(fmt.Sprintf("quota: %s=%d is below %d", k, v, Unlimited))
	}
	out := Limits{set: make(map[Key]int, len(l.set)+1)}
	for key, val := range l.set {
		out.set[key] = val
	}
	out.set[k] = v
	return out
}

// For returns the defaults with the given limits changed, for tests.
func For(m map[Key]int) Limits {
	var l Limits
	for k, v := range m {
		l = l.With(k, v)
	}
	return l
}

// Parse reads a -quotas setting, "key=value,key=value", on top of base.
// A value is a count or -1 for unlimited. Keys in reserved are refused
// with the flag that sets them instead.
func Parse(base Limits, spec string, reserved map[Key]string) (Limits, error) {
	out := base
	seen := make(map[Key]bool)
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			return Limits{}, fmt.Errorf("quota %q: want key=value", item)
		}
		k := Key(strings.TrimSpace(name))
		if _, known := defaults[k]; !known {
			return Limits{}, fmt.Errorf("unknown quota %q (known: %s)", k, strings.Join(keyNames(), ", "))
		}
		if flag, ok := reserved[k]; ok {
			return Limits{}, fmt.Errorf("quota %q is set with %s", k, flag)
		}
		if seen[k] {
			return Limits{}, fmt.Errorf("quota %q is set twice", k)
		}
		seen[k] = true
		v, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || v < Unlimited {
			return Limits{}, fmt.Errorf("quota %s=%s: want a count, or -1 for unlimited", k, value)
		}
		out = out.With(k, v)
	}
	return out, nil
}

// Keys returns every key in alphabetical order.
func Keys() []Key {
	out := make([]Key, 0, len(defaults))
	for k := range defaults {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Default returns a key's default limit and where it comes from.
func Default(k Key) (value int, source string, ok bool) {
	d, ok := defaults[k]
	return d.value, d.source, ok
}

func keyNames() []string {
	keys := Keys()
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = string(k)
	}
	return out
}

// Format writes limits as a -quotas setting ("key=value,..." in key
// order), so tests can derive WEISTACK_QUOTAS from the counts they need.
// It panics on an unknown key or a value below Unlimited, as With does.
func Format(m map[Key]int) string {
	keys := make([]Key, 0, len(m))
	for k, v := range m {
		_ = Limits{}.With(k, v) // validates
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = string(k) + "=" + strconv.Itoa(m[k])
	}
	return strings.Join(parts, ",")
}
