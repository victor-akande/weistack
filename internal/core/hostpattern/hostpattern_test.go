package hostpattern

import "testing"

func TestMatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"apiexplorer.*.myhuaweicloud.com", "apiexplorer.ap-southeast-3.myhuaweicloud.com", true},
		{"apiexplorer.*.myhuaweicloud.com", "APIExplorer.cn-north-4.myhuaweicloud.com.", true},
		{"apiexplorer.*.myhuaweicloud.com", "apiexplorer.myhuaweicloud.com", false},
		{"apiexplorer.*.myhuaweicloud.com", "apiexplorer.a.b.myhuaweicloud.com", false},
		{"apiexplorer.*.myhuaweicloud.com", "xapiexplorer.ap-southeast-3.myhuaweicloud.com", false},
		{"{region}-hwcloudcli.obs.{region}.myhuaweicloud.com", "ap-southeast-3-hwcloudcli.obs.ap-southeast-3.myhuaweicloud.com", true},
		{"{region}-hwcloudcli.obs.{region}.myhuaweicloud.com", "cn-north-4-hwcloudcli.obs.cn-north-4.myhuaweicloud.com", true},
		// A user's own bucket that ends like KooCLI's is not KooCLI's.
		{"{region}-hwcloudcli.obs.{region}.myhuaweicloud.com", "my-hwcloudcli.obs.ap-southeast-1.myhuaweicloud.com", false},
		{"{region}-hwcloudcli.obs.{region}.myhuaweicloud.com", "ap-southeast-1-hwcloudcli.obs.ap-southeast-3.myhuaweicloud.com", false},
		{"exact.example.com", "exact.example.com", true},
		{"exact.example.com", "sub.exact.example.com", false},
	}
	for _, c := range cases {
		p, err := Compile(c.pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", c.pattern, err)
		}
		if got := p.Match(c.host); got != c.want {
			t.Errorf("%q matching %q = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestCompileRejects(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "a..b", "*.com/x", "{zone}.example.com", "a b.com", "{region", "ex*mple.com"} {
		if _, err := Compile(bad); err == nil {
			t.Errorf("Compile(%q) accepted it", bad)
		}
	}
	p, err := Compile(" Apiexplorer.*.Example.com. ")
	if err != nil || p.String() != "apiexplorer.*.example.com" {
		t.Errorf("normalised pattern = %v, %v", p, err)
	}
}
