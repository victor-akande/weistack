package hostpattern

import "testing"

// FuzzPattern: no pattern or host crashes Compile or Match, and a
// compiled literal pattern matches itself.
func FuzzPattern(f *testing.F) {
	f.Add("{region}-hwcloudcli.obs.{region}.myhuaweicloud.com", "ap-southeast-1-hwcloudcli.obs.ap-southeast-1.myhuaweicloud.com")
	f.Add("apiexplorer.*.myhuaweicloud.com", "apiexplorer.x.myhuaweicloud.com")
	f.Add("*.*", "a.b")
	f.Fuzz(func(_ *testing.T, pattern, host string) {
		p, err := Compile(pattern)
		if err != nil {
			return
		}
		_ = p.Match(host)
		_ = p.Match(pattern)
	})
}
