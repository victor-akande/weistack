package ims

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

func TestPublicImagesMatchGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	out := e.expect(t, "list_images_public", http.MethodGet, "/v2/cloudimages?__platform=CentOS", "")
	id := decodeInto[listImagesResponse](t, out).Images[0].ID

	e.expect(t, "show_image", http.MethodGet, "/v2/images/"+id, "")
	e.expect(t, "list_images_page", http.MethodGet, "/v2/cloudimages?sort_key=name&sort_dir=asc&limit=1", "")
	e.expect(t, "list_images_empty", http.MethodGet, "/v2/cloudimages?__imagetype=private", "")
	e.expect(t, "list_images_empty", http.MethodGet, "/v2/cloudimages?name=no-such-image", "")
	e.expect(t, "error_image_not_found", http.MethodGet, "/v2/images/"+unknownID, "")
	e.expect(t, "error_image_not_found", http.MethodGet, "/v2/images/not-a-uuid", "")
}

func TestSeededImages(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	all, err := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 8 {
		t.Fatalf("%d public images seeded, want 8", len(all))
	}
	// The default order (newest first) follows the seed file.
	if all[0].Name != "Ubuntu 22.04 server 64bit" || all[7].OSType != "Windows" {
		t.Errorf("order: first %q, last %q", all[0].Name, all[7].Name)
	}

	seen := map[string]bool{}
	for _, img := range all {
		if !uuidRE.MatchString(img.ID) || seen[img.ID] {
			t.Errorf("image %q has a bad or duplicate ID %q", img.Name, img.ID)
		}
		seen[img.ID] = true
		if img.Visibility != VisibilityPublic || img.ImageType != TypeGold || img.Status != StatusActive ||
			!img.Protected || img.Owner != publicOwner || img.ActiveAt == nil {
			t.Errorf("image %q is not a well-formed public image: %+v", img.Name, img)
		}
		if img.Self != "/v2/images/"+img.ID || img.File != img.Self+"/file" {
			t.Errorf("image %q links: %q %q", img.Name, img.Self, img.File)
		}
	}

	arm, _ := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{Name: "Huawei Cloud EulerOS 2.0 Standard 64 bit for kAi2p"})
	if len(arm) != 1 || arm[0].SupportArm != "true" || arm[0].HwFirmwareType != "uefi" {
		t.Errorf("ARM image: %+v", arm)
	}
}

// A learner's Terraform file may hard-code an image ID: it must be the
// same on every machine and after every restart or reset.
func TestSeededImageIDsAreStable(t *testing.T) {
	t.Parallel()

	const ubuntu = "455b5860-f96d-5d89-baaa-ec6adb758c5b"
	first := newEnv(t)
	second := newEnv(t)
	for _, e := range []*env{first, second} {
		img, err := e.svc.GetImage(t.Context(), testTenant, ubuntu)
		if err != nil || img.Name != "Ubuntu 22.04 server 64bit" {
			t.Fatalf("GetImage(%s) = %q, %v", ubuntu, img.Name, err)
		}
	}

	// Every region has the same images under the same IDs.
	other := Tenant{Region: "af-south-1", ProjectID: testProject}
	if img, err := first.svc.GetImage(t.Context(), other, ubuntu); err != nil || img.Name == "" {
		t.Fatalf("another region: %v", err)
	}

	// After a reset wipes the store, they come back.
	if err := first.store.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := first.svc.Reset(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := first.svc.GetImage(t.Context(), testTenant, ubuntu); err != nil {
		t.Fatalf("after reset: %v", err)
	}
}

func TestSeedingIsIdempotentWithPersistence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	for run := range 2 {
		st, err := store.OpenBolt(path)
		if err != nil {
			t.Fatal(err)
		}
		e := newEnvWith(t, st, "")
		all, err := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{})
		if err != nil || len(all) != 8 {
			t.Fatalf("run %d: %d images, %v; want 8", run, len(all), err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListFiltersSortingAndPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	const (
		ubuntu22 = "Ubuntu 22.04 server 64bit"
		ubuntu20 = "Ubuntu 20.04 server 64bit"
		windows  = "Windows Server 2019 Standard 64bit English"
	)
	q := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return "?" + v.Encode()
	}

	tests := []struct{ query, want string }{
		{q("__platform", "Ubuntu"), ubuntu22 + " | " + ubuntu20},
		{q("__platform", "Ubuntu", "sort_key", "name", "sort_dir", "asc"), ubuntu20 + " | " + ubuntu22},
		{q("__platform", "Ubuntu", "sort_key", "created_at", "sort_dir", "asc"), ubuntu20 + " | " + ubuntu22},
		{q("__os_type", "Windows"), windows},
		{q("name", ubuntu20), ubuntu20},
		{q("__imagetype", "gold", "__platform", "Windows"), windows},
		{q("visibility", "public", "__os_type", "Windows", "status", "active", "__os_bit", "64"), windows},
		{q("owner", publicOwner, "__platform", "Windows", "protected", "true"), windows},
		{q("disk_format", "zvhd2", "container_format", "bare", "virtual_env_type", "FusionCompute", "__platform", "Windows"), windows},
		{q("protected", "false"), ""},
		{q("status", "queued"), ""},
		{q("visibility", "private"), ""},
		{q("tag", "anything"), ""},
		{q("__os_bit", "32"), ""},
		{q("__platform", "Ubuntu", "limit", "1"), ubuntu22 + " +more"},
		{q("__platform", "Ubuntu", "limit", "2"), ubuntu22 + " | " + ubuntu20},
	}
	for _, tt := range tests {
		if got := e.names(t, tt.query); got != tt.want {
			t.Errorf("list %s\n got %q\nwant %q", tt.query, got, tt.want)
		}
	}

	// Walking every page sees each image once.
	seen := map[string]int{}
	marker, pages := "", 0
	for {
		pages++
		query := "?limit=3&sort_key=id"
		if marker != "" {
			query += "&marker=" + marker
		}
		_, out := e.call(t, testProject, http.MethodGet, "/v2/cloudimages"+query, "")
		res := decodeInto[listImagesResponse](t, out)
		for _, img := range res.Images {
			seen[img.ID]++
		}
		if res.PageInfo == nil {
			break
		}
		marker = res.PageInfo.NextMarker
	}
	if pages != 3 || len(seen) != 8 {
		t.Errorf("paging took %d pages and saw %d images, want 3 and 8", pages, len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("image %s seen %d times", id, n)
		}
	}

	// The filter by ID is what Terraform's image data source uses.
	id := decodeInto[listImagesResponse](t, e.expect(t, "list_images_public", http.MethodGet, "/v2/cloudimages?__platform=CentOS", "")).Images[0].ID
	if got := e.names(t, "?id="+id); got != "CentOS 7.9 64bit" {
		t.Errorf("filter by id = %q", got)
	}

	for _, bad := range []string{
		"?limit=0", "?limit=1001", "?limit=x", "?marker=" + unknownID,
		"?sort_key=colour", "?sort_dir=sideways", "?protected=maybe",
	} {
		e.expect(t, "error_invalid_request", http.MethodGet, "/v2/cloudimages"+bad, "")
	}
	if got := e.names(t, "?sort_key=size&sort_dir=desc&limit=1"); !strings.HasSuffix(got, "+more") {
		t.Errorf("sort by size: %q", got)
	}
}

func TestTenantComesFromTheProjectHeader(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	// A private image in another project, placed directly in the store.
	private := Image{ID: unknownID, Name: "theirs", ImageType: TypePrivate, Visibility: VisibilityPrivate, Status: StatusActive, Tags: []string{}}
	if err := e.svc.privateImages(Tenant{Region: testRegion, ProjectID: otherProject}).Create(t.Context(), private.ID, private); err != nil {
		t.Fatal(err)
	}

	count := func(project string) int {
		t.Helper()
		status, out := e.call(t, project, http.MethodGet, "/v2/cloudimages?__imagetype=private", "")
		if status != http.StatusOK {
			t.Fatalf("list as %q: %d %s", project, status, out)
		}
		return len(decodeInto[listImagesResponse](t, out).Images)
	}
	if n := count(otherProject); n != 1 {
		t.Errorf("owner sees %d private images, want 1", n)
	}
	if n := count(testProject); n != 0 {
		t.Errorf("another project sees %d private images, want 0", n)
	}
	// Without the header, and with a malformed one, the default project applies.
	if n := count(""); n != 0 {
		t.Errorf("default project sees %d private images, want 0", n)
	}
	if n := count("not-a-project-id"); n != 0 {
		t.Errorf("malformed header: sees %d private images, want 0", n)
	}

	if status, _ := e.call(t, otherProject, http.MethodGet, "/v2/images/"+unknownID, ""); status != http.StatusOK {
		t.Errorf("owner cannot show its image: %d", status)
	}
	if status, _ := e.call(t, testProject, http.MethodGet, "/v2/images/"+unknownID, ""); status != http.StatusNotFound {
		t.Errorf("another project can show the image: %d", status)
	}
}

func writeSeed(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "images.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSeedDirExtendsAndOverrides(t *testing.T) {
	t.Parallel()

	dir := writeSeed(t, `
images:
  - name: Rocky Linux 9.0 64bit          # a new image
    os_version: Rocky Linux 9.0 64bit
    platform: Rocky
    id: 11111111-2222-4333-8444-555555555555
  - name: CentOS 7.9 64bit               # replaces the built-in entry
    os_version: CentOS 7.9 64bit
    platform: CentOS
    min_disk: 100
    min_ram: 4096
`)
	e := newEnvWith(t, store.NewMemory(), dir)

	all, err := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{})
	if err != nil || len(all) != 9 {
		t.Fatalf("%d images, %v; want the 8 built-in plus 1", len(all), err)
	}
	rocky, err := e.svc.GetImage(t.Context(), testTenant, "11111111-2222-4333-8444-555555555555")
	if err != nil || rocky.Name != "Rocky Linux 9.0 64bit" || rocky.MinDisk != 40 || rocky.OSType != "Linux" {
		t.Fatalf("added image = %+v, %v", rocky, err)
	}
	centos, _ := e.svc.ListImages(t.Context(), testTenant, ListImagesFilter{Name: "CentOS 7.9 64bit"})
	if len(centos) != 1 || centos[0].MinDisk != 100 || centos[0].MinRAM != 4096 {
		t.Fatalf("overridden image = %+v", centos)
	}

	// A seed directory without images.yaml is fine.
	if _, err := loadSeedImages(t.TempDir()); err != nil {
		t.Fatalf("empty seed dir: %v", err)
	}
}

func TestInvalidSeedFilesAreRejected(t *testing.T) {
	t.Parallel()

	base := "images:\n  - name: X\n    os_version: X 1\n    platform: X\n"
	tests := map[string]string{
		"not yaml":           "images: [",
		"unknown field":      base + "    colour: blue\n",
		"missing name":       "images:\n  - os_version: X\n    platform: X\n",
		"missing os_version": "images:\n  - name: X\n    platform: X\n",
		"bad os_type":        base + "    os_type: BeOS\n",
		"bad arch":           base + "    arch: mips\n",
		"bad firmware":       base + "    firmware: coreboot\n",
		"bad min_disk":       base + "    min_disk: 5000\n",
		"negative min_ram":   base + "    min_ram: -1\n",
		"bad id":             base + "    id: NOT-A-UUID\n",
		"repeated name":      base + "  - name: X\n    os_version: X 2\n    platform: X\n",
		"id used twice":      base + "    id: 11111111-2222-4333-8444-555555555555\n  - name: Y\n    os_version: Y\n    platform: Y\n    id: 11111111-2222-4333-8444-555555555555\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadSeedImages(writeSeed(t, content)); err == nil {
				t.Fatal("the seed file was accepted")
			}
		})
	}

	// An unreadable seed file is an error, not silently skipped.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "images.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSeedImages(dir); err == nil {
		t.Fatal("a directory named images.yaml was accepted")
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New succeeded without dependencies")
	}
}

func TestNameUUID(t *testing.T) {
	t.Parallel()
	a, b := nameUUID("a"), nameUUID("b")
	if a == b || a != nameUUID("a") {
		t.Fatalf("nameUUID is not a stable function of its input: %q %q", a, b)
	}
	if !uuidRE.MatchString(a) || a[14] != '5' {
		t.Fatalf("%q is not a version 5 UUID", a)
	}
}

func TestTimeJSON(t *testing.T) {
	t.Parallel()
	var tm Time
	if err := tm.UnmarshalJSON([]byte(`"2018-09-06T14:03:27Z"`)); err != nil {
		t.Fatal(err)
	}
	if b, _ := tm.MarshalJSON(); string(b) != `"2018-09-06T14:03:27Z"` {
		t.Fatalf("round trip = %s", b)
	}
	for _, bad := range []string{`1`, `"2018-09-06"`, `"`} {
		if err := tm.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("UnmarshalJSON(%s) succeeded", bad)
		}
	}
}
