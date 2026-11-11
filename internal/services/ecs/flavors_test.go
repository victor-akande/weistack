package ecs

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victor-akande/weistack/internal/core/store"
)

const flavorsPath = "/v1/{project}/cloudservers/flavors"

func TestFlavorsAndZonesMatchGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	e.expect(t, "list_flavors_one", http.MethodGet, flavorsPath+"?flavor_id=s6.large.2", "")
	e.expect(t, "list_flavors_one", http.MethodGet, flavorsPath+"?flavor_id=s6.large.2&availability_zone=ap-southeast-1b", "")
	e.expect(t, "list_flavors_empty", http.MethodGet, flavorsPath+"?flavor_id=z9.huge.1", "")
	// A zone of another region sells nothing here.
	e.expect(t, "list_flavors_empty", http.MethodGet, flavorsPath+"?availability_zone=cn-north-4a", "")
	e.expect(t, "list_zones", http.MethodGet, "/v2.1/{project}/os-availability-zone", "")

	for _, bad := range []string{"?limit=0", "?limit=x", "?marker=no.such.flavor"} {
		e.expect(t, "error_ecs_0005", http.MethodGet, flavorsPath+bad, "")
	}
}

func TestSeededFlavors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	all := e.svc.ListFlavors(testTenant, "")
	if len(all) != 20 {
		t.Fatalf("%d flavors seeded, want 20", len(all))
	}

	// vCPU and memory of real flavors.
	want := map[string][2]int{
		"s6.small.1": {1, 1024}, "s6.large.2": {2, 4096}, "s6.2xlarge.4": {8, 32768},
		"c7.large.2": {2, 4096}, "c7.xlarge.4": {4, 16384},
		"m7.large.8": {2, 16384}, "m7.2xlarge.8": {8, 65536},
		"kc1.large.2": {2, 4096},
	}
	for name, spec := range want {
		f, ok := e.svc.FlavorByName(name)
		if !ok || f.VCPUs != spec[0] || f.RAM != spec[1] {
			t.Errorf("flavor %s = %+v (found %v), want %d vCPUs and %d MiB", name, f, ok, spec[0], spec[1])
		}
	}
	if _, ok := e.svc.FlavorByName("z9.huge.1"); ok {
		t.Error("an unknown flavor was found")
	}

	arm, _ := e.svc.FlavorByName("kc1.large.2")
	if arm.Arch != ArchARM || arm.view(testTenant).OSExtraSpec.CPUArchitecture != "arm64" {
		t.Errorf("ARM flavor: %+v", arm)
	}
	c7, _ := e.svc.FlavorByName("c7.xlarge.4")
	if v := c7.view(testTenant); v.OSExtraSpec.Generation != "c7" || v.OSExtraSpec.PerformanceType != "computingv3" ||
		v.VCPUs != "4" || !strings.Contains(v.Links[0].Href, "/"+testProject+"/flavors/c7.xlarge.4") {
		t.Errorf("c7 view: %+v", v)
	}
}

func TestFlavorPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	seen := map[string]int{}
	marker := ""
	for pages := 0; pages < 20; pages++ {
		q := "?limit=7"
		if marker != "" {
			q += "&marker=" + marker
		}
		status, out := e.call(t, http.MethodGet, flavorsPath+q, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, status, out)
		}
		page := decodeInto[listFlavorsResponse](t, out).Flavors
		if len(page) == 0 {
			break
		}
		for _, f := range page {
			seen[f.ID]++
		}
		marker = page[len(page)-1].ID
	}
	if len(seen) != 20 {
		t.Fatalf("paging saw %d flavors, want 20", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("flavor %s seen %d times", id, n)
		}
	}
}

func TestZonesFollowTheRequestRegion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r, _ := http.NewRequest(http.MethodGet, "/v2.1/"+testProject+"/os-availability-zone", nil)
	r.Host = "ecs.af-south-1.myhuaweicloud.com"
	w := newRecorder(e, r)
	if !strings.Contains(w, `"zoneName":"af-south-1a"`) || strings.Contains(w, "ap-southeast-1") {
		t.Errorf("zones for af-south-1: %s", w)
	}
}

func writeFlavorSeed(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flavors.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSeedDirExtendsAndOverridesFlavors(t *testing.T) {
	t.Parallel()

	dir := writeFlavorSeed(t, `
flavors:
  - {name: t6.small.1, vcpus: 1, ram: 1024}                  # new
  - {name: s6.small.1, vcpus: 1, ram: 2048}                  # replaces the built-in
`)
	e := newEnvWith(t, store.NewMemory(), dir)
	if n := len(e.svc.ListFlavors(testTenant, "")); n != 21 {
		t.Fatalf("%d flavors, want the 20 built-in plus 1", n)
	}
	if f, ok := e.svc.FlavorByName("t6.small.1"); !ok || f.Arch != ArchX86 || f.PerformanceType != "normal" {
		t.Errorf("added flavor = %+v (found %v)", f, ok)
	}
	if f, _ := e.svc.FlavorByName("s6.small.1"); f.RAM != 2048 {
		t.Errorf("overridden flavor = %+v", f)
	}
	if _, err := loadFlavors(t.TempDir()); err != nil {
		t.Fatalf("empty seed dir: %v", err)
	}
}

func TestInvalidFlavorSeedsAreRejected(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"not yaml":      "flavors: [",
		"unknown field": "flavors:\n  - {name: a.b, vcpus: 1, ram: 1024, gpus: 1}\n",
		"missing name":  "flavors:\n  - {vcpus: 1, ram: 1024}\n",
		"bad name":      "flavors:\n  - {name: Large, vcpus: 1, ram: 1024}\n",
		"no vcpus":      "flavors:\n  - {name: a.b, ram: 1024}\n",
		"tiny ram":      "flavors:\n  - {name: a.b, vcpus: 1, ram: 4}\n",
		"bad arch":      "flavors:\n  - {name: a.b, vcpus: 1, ram: 1024, arch: mips}\n",
		"repeated name": "flavors:\n  - {name: a.b, vcpus: 1, ram: 1024}\n  - {name: a.b, vcpus: 2, ram: 2048}\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadFlavors(writeFlavorSeed(t, content)); err == nil {
				t.Fatal("the seed file was accepted")
			}
		})
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "flavors.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFlavors(dir); err == nil {
		t.Fatal("a directory named flavors.yaml was accepted")
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New succeeded without dependencies")
	}
}
