package obs

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// parsed is a listing response reduced to what the tests assert on.
type parsed struct {
	Keys                  []string `xml:"Contents>Key"`
	Prefixes              []string `xml:"CommonPrefixes>Prefix"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextMarker            string   `xml:"NextMarker"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	KeyCount              *int     `xml:"KeyCount"`
	MaxKeys               int      `xml:"MaxKeys"`
}

func (e *env) list(t *testing.T, bucket, query string) (parsed, string) {
	t.Helper()
	res := e.get(t, "/"+bucket+"?"+query, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("list %q: %d %s", query, res.Status, res.Body)
	}
	var p parsed
	if err := xml.Unmarshal([]byte(res.Body), &p); err != nil {
		t.Fatalf("list %q: invalid XML: %v\n%s", query, err, res.Body)
	}
	return p, res.Body
}

// summary renders a page as "keys | prefixes [+more]".
func (p parsed) summary() string {
	s := strings.Join(p.Keys, ",") + " | " + strings.Join(p.Prefixes, ",")
	if p.IsTruncated {
		s += " +more"
	}
	return s
}

// tree fills a bucket with a small directory-like layout.
func (e *env) tree(t *testing.T) {
	t.Helper()
	e.bucket(t, "tree")
	for _, k := range []string{
		"a.txt", "b.txt",
		"docs/guide.md", "docs/api/v1.md", "docs/api/v2.md",
		"img/logo.png", "img/icons/a.svg", "img/icons/b.svg",
		"z-last",
	} {
		mustStatus(t, e.put(t, "/tree/"+k, k, nil), http.StatusOK)
	}
}

func TestListObjectsV1ExactXML(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	mustStatus(t, e.put(t, "/data/dir/b", "bb", nil), 200)
	mustStatus(t, e.put(t, "/data/a", "a", nil), 200)

	_, body := e.list(t, "data", "delimiter=/")
	want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<ListBucketResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">` +
		`<Name>data</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><Delimiter>/</Delimiter><IsTruncated>false</IsTruncated>` +
		`<Contents><Key>a</Key><LastModified>2026-11-10T09:30:00.000Z</LastModified><ETag>&#34;` + md5hex("a") + `&#34;</ETag><Size>1</Size>` +
		`<Owner><ID>` + ownerID("AKALICE") + `</ID></Owner><StorageClass>STANDARD</StorageClass></Contents>` +
		`<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>` +
		`</ListBucketResult>`
	if body != want {
		t.Errorf("listing =\n%s\nwant\n%s", body, want)
	}

	// An empty bucket.
	e.bucket(t, "empty")
	p, body := e.list(t, "empty", "")
	if len(p.Keys) != 0 || p.IsTruncated || !strings.Contains(body, "<Marker></Marker>") || strings.Contains(body, "KeyCount") {
		t.Errorf("empty v1 listing: %s", body)
	}
}

func TestListObjectsPrefixAndDelimiter(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.tree(t)

	tests := []struct{ query, want string }{
		// Flat: every key, in byte order.
		{"", "a.txt,b.txt,docs/api/v1.md,docs/api/v2.md,docs/guide.md,img/icons/a.svg,img/icons/b.svg,img/logo.png,z-last | "},
		// One "directory level" at a time.
		{"delimiter=/", "a.txt,b.txt,z-last | docs/,img/"},
		{"delimiter=/&prefix=docs/", "docs/guide.md | docs/api/"},
		{"delimiter=/&prefix=docs/api/", "docs/api/v1.md,docs/api/v2.md | "},
		{"delimiter=/&prefix=img/", "img/logo.png | img/icons/"},
		// A prefix need not end at a delimiter.
		{"prefix=docs/a", "docs/api/v1.md,docs/api/v2.md | "},
		{"delimiter=/&prefix=do", " | docs/"},
		{"prefix=img/icons/b", "img/icons/b.svg | "},
		{"prefix=nothing", " | "},
		// Any string can be the delimiter.
		{"delimiter=.", "z-last | a.,b.,docs/api/v1.,docs/api/v2.,docs/guide.,img/icons/a.,img/icons/b.,img/logo."},
		{"delimiter=api", "a.txt,b.txt,docs/guide.md,img/icons/a.svg,img/icons/b.svg,img/logo.png,z-last | docs/api"},
		// Markers.
		{"marker=docs/guide.md", "img/icons/a.svg,img/icons/b.svg,img/logo.png,z-last | "},
		{"marker=zzz", " | "},
		{"delimiter=/&marker=docs/", "z-last | img/"},
		{"delimiter=/&marker=b.txt", "z-last | docs/,img/"},
		// Limits.
		{"max-keys=2", "a.txt,b.txt |  +more"},
		{"max-keys=0", " | "},
		{"max-keys=9", "a.txt,b.txt,docs/api/v1.md,docs/api/v2.md,docs/guide.md,img/icons/a.svg,img/icons/b.svg,img/logo.png,z-last | "},
		{"max-keys=5000", "a.txt,b.txt,docs/api/v1.md,docs/api/v2.md,docs/guide.md,img/icons/a.svg,img/icons/b.svg,img/logo.png,z-last | "},
		// A common prefix counts as one entry towards the limit.
		{"delimiter=/&max-keys=3", "a.txt,b.txt | docs/ +more"},
		{"delimiter=/&max-keys=4", "a.txt,b.txt | docs/,img/ +more"},
	}
	for _, tt := range tests {
		for _, version := range []string{"", "&list-type=2"} {
			query := tt.query + version
			if version != "" {
				query = strings.Replace(query, "marker=", "start-after=", 1)
			}
			p, _ := e.list(t, "tree", query)
			if got := p.summary(); got != tt.want {
				t.Errorf("list %q\n got %q\nwant %q", query, got, tt.want)
			}
		}
	}

	p, _ := e.list(t, "tree", "max-keys=5000")
	if p.MaxKeys != 1000 {
		t.Errorf("MaxKeys = %d, want it capped at 1000", p.MaxKeys)
	}
}

// Walking a listing page by page must return every entry exactly once,
// in order, whatever the page size.
func TestListObjectsPagingIsComplete(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.tree(t)

	walk := func(v2 bool, base string, size int) (keys, prefixes []string) {
		t.Helper()
		next := ""
		for pages := 0; ; pages++ {
			if pages > 50 {
				t.Fatalf("paging did not terminate (v2=%v, %q, size %d)", v2, base, size)
			}
			q := fmt.Sprintf("%s&max-keys=%d", base, size)
			switch {
			case v2:
				q += "&list-type=2"
				if next != "" {
					q += "&continuation-token=" + url.QueryEscape(next)
				}
			case next != "":
				q += "&marker=" + url.QueryEscape(next)
			}
			p, body := e.list(t, "tree", q)
			keys = append(keys, p.Keys...)
			prefixes = append(prefixes, p.Prefixes...)
			if v2 && (p.KeyCount == nil || *p.KeyCount != len(p.Keys)+len(p.Prefixes)) {
				t.Fatalf("KeyCount does not match the page: %s", body)
			}
			if !p.IsTruncated {
				if p.NextMarker != "" || p.NextContinuationToken != "" {
					t.Fatalf("a final page carries a next position: %s", body)
				}
				return keys, prefixes
			}
			if next = p.NextMarker; v2 {
				next = p.NextContinuationToken
			}
			if next == "" {
				t.Fatalf("a truncated page has no next position: %s", body)
			}
		}
	}

	flat, _ := e.list(t, "tree", "")
	level, _ := e.list(t, "tree", "delimiter=/")
	for _, v2 := range []bool{false, true} {
		for size := 1; size <= 10; size++ {
			keys, prefixes := walk(v2, "", size)
			if strings.Join(keys, ",") != strings.Join(flat.Keys, ",") || len(prefixes) != 0 {
				t.Errorf("v2=%v flat, page size %d: %v", v2, size, keys)
			}
			keys, prefixes = walk(v2, "delimiter=/", size)
			if strings.Join(keys, ",") != strings.Join(level.Keys, ",") || strings.Join(prefixes, ",") != strings.Join(level.Prefixes, ",") {
				t.Errorf("v2=%v delimited, page size %d: keys %v prefixes %v", v2, size, keys, prefixes)
			}
		}
	}
}

func TestListObjectsV2Fields(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.tree(t)

	_, body := e.list(t, "tree", "list-type=2&max-keys=1&start-after=a.txt")
	for _, sub := range []string{"<KeyCount>1</KeyCount>", "<StartAfter>a.txt</StartAfter>", "<NextContinuationToken>", "<Key>b.txt</Key>"} {
		if !strings.Contains(body, sub) {
			t.Errorf("v2 listing does not contain %s: %s", sub, body)
		}
	}
	// No v1 fields, and no owner unless asked for.
	for _, sub := range []string{"<Marker>", "<NextMarker>", "<Owner>"} {
		if strings.Contains(body, sub) {
			t.Errorf("v2 listing contains %s: %s", sub, body)
		}
	}
	if _, body := e.list(t, "tree", "list-type=2&fetch-owner=true&max-keys=1"); !strings.Contains(body, "<Owner><ID>") {
		t.Errorf("fetch-owner=true did not include the owner: %s", body)
	}
	// The token passed in is echoed, and takes precedence over start-after.
	p, _ := e.list(t, "tree", "list-type=2&max-keys=2")
	second, body := e.list(t, "tree", "list-type=2&max-keys=2&start-after=z&continuation-token="+url.QueryEscape(p.NextContinuationToken))
	if strings.Join(second.Keys, ",") != "docs/api/v1.md,docs/api/v2.md" || !strings.Contains(body, "<ContinuationToken>"+p.NextContinuationToken+"</ContinuationToken>") {
		t.Errorf("second page: %s", body)
	}

	wantError(t, e.get(t, "/tree?list-type=2&continuation-token=!!!", nil), 400, "InvalidArgument")
	wantError(t, e.get(t, "/tree?max-keys=-1", nil), 400, "InvalidArgument")
	wantError(t, e.get(t, "/tree?max-keys=lots", nil), 400, "InvalidArgument")
	wantError(t, e.get(t, "/tree?encoding-type=base64", nil), 400, "InvalidArgument")
	wantError(t, e.get(t, "/no-such-bucket", nil), 404, "NoSuchBucket")
}

func TestListObjectsURLEncoding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "data")
	// Keys with characters that need care in XML or URLs.
	keys := []string{"dir with space/file one.txt", "a&b<c>.txt", "plus+sign", "日本語"}
	for _, k := range keys {
		mustStatus(t, e.put(t, "/data/"+url.PathEscape(k), "x", nil), 200)
	}

	// Without encoding the keys are returned as they are (XML-escaped).
	plain, body := e.list(t, "data", "")
	if len(plain.Keys) != 4 || !strings.Contains(body, "a&amp;b&lt;c&gt;.txt") {
		t.Errorf("plain listing: %s", body)
	}
	for _, k := range keys {
		found := false
		for _, got := range plain.Keys {
			found = found || got == k
		}
		if !found {
			t.Errorf("key %q missing from %v", k, plain.Keys)
		}
	}

	// With encoding-type=url, which AWS SDKs request by default, keys
	// are percent-encoded but slashes stay readable.
	enc, body := e.list(t, "data", "encoding-type=url&delimiter=/&prefix="+url.QueryEscape("dir with space/"))
	if !strings.Contains(body, "<EncodingType>url</EncodingType>") || !strings.Contains(body, "<Prefix>dir+with+space/</Prefix>") {
		t.Errorf("encoded listing: %s", body)
	}
	if len(enc.Keys) != 1 || enc.Keys[0] != "dir+with+space/file+one.txt" {
		t.Errorf("encoded keys = %v", enc.Keys)
	}
	if decoded, err := url.QueryUnescape(enc.Keys[0]); err != nil || decoded != keys[0] {
		t.Errorf("encoded key does not decode back: %q, %v", decoded, err)
	}
	all, _ := e.list(t, "data", "encoding-type=url")
	for _, got := range all.Keys {
		decoded, err := url.QueryUnescape(got)
		if err != nil || strings.ContainsAny(got, " <>&") {
			t.Errorf("encoded key %q is not URL-safe (%v)", got, err)
		}
		_ = decoded
	}
}

func TestListingScalesToManyObjects(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.bucket(t, "many")
	const n = 1500
	for i := range n {
		// Written straight to the store: 1500 HTTP uploads add nothing here.
		key := fmt.Sprintf("logs/%04d.log", i)
		if err := e.svc.objects("many").Create(t.Context(), key, Object{Key: key, ETag: "x", Modified: e.now}); err != nil {
			t.Fatal(err)
		}
	}

	first, _ := e.list(t, "many", "")
	if len(first.Keys) != 1000 || !first.IsTruncated || first.NextMarker != "logs/0999.log" {
		t.Fatalf("first page: %d keys, truncated %v, next %q", len(first.Keys), first.IsTruncated, first.NextMarker)
	}
	second, _ := e.list(t, "many", "marker="+first.NextMarker)
	if len(second.Keys) != 500 || second.IsTruncated || second.Keys[0] != "logs/1000.log" || second.Keys[499] != "logs/1499.log" {
		t.Fatalf("second page: %d keys, truncated %v", len(second.Keys), second.IsTruncated)
	}
	rolled, _ := e.list(t, "many", "delimiter=/")
	if rolled.summary() != " | logs/" {
		t.Fatalf("1500 keys under one prefix roll up to %q", rolled.summary())
	}
}
