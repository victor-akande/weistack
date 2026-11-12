package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/victor-akande/weistack/internal/core/store"
)

// fixtureIDs are the resources testdata/upgrade/generate.sh created.
type fixtureIDs struct {
	Project       string `json:"project"`
	VPC           string `json:"vpc"`
	Subnet        string `json:"subnet"`
	SecurityGroup string `json:"security_group"`
	Server        string `json:"server"`
	ImageJob      string `json:"image_job"`
	Bucket        string `json:"bucket"`
	Object        string `json:"object"`
	BucketOwner   string `json:"bucket_owner"`
	RDS           string `json:"rds"`
}

// copyFixture copies a released data directory into a temp dir, so the
// test never changes the committed files.
func copyFixture(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func (i *instance) getAs(t *testing.T, path, authorization string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+i.addr+path, nil)
	req.Header.Set("Authorization", authorization)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

// TestUpgradeFromReleasedData starts the current code on data written by
// every released version and reads all of it back.
func TestUpgradeFromReleasedData(t *testing.T) {
	t.Parallel()
	dirs, err := filepath.Glob(filepath.Join("testdata", "upgrade", "v*", "data"))
	if err != nil || len(dirs) < 2 {
		t.Fatalf("release fixtures = %v, %v; want one per release", dirs, err)
	}
	for _, dir := range dirs {
		version := filepath.Base(filepath.Dir(dir))
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			data := copyFixture(t, dir)
			raw, err := os.ReadFile(filepath.Join(data, "ids.json"))
			if err != nil {
				t.Fatal(err)
			}
			var ids fixtureIDs
			if err := json.Unmarshal(raw, &ids); err != nil {
				t.Fatal(err)
			}

			// As a user upgrades: the same flags, a newer binary.
			inst := startInstance(t, map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": data})
			if got := inst.projectID(t); got != ids.Project {
				t.Fatalf("project ID %s, want %s from the release's project_id file", got, ids.Project)
			}
			p := ids.Project
			expect := func(path string, wants ...string) {
				t.Helper()
				status, body := inst.get(t, path)
				if status != http.StatusOK {
					t.Fatalf("GET %s: %d %s", path, status, body)
				}
				for _, want := range wants {
					if !strings.Contains(body, want) {
						t.Errorf("GET %s lacks %s: %s", path, want, body)
					}
				}
			}
			expect("/vpc/v1/"+p+"/vpcs/"+ids.VPC, `"name":"fixture-vpc"`, `"status":"OK"`)
			expect("/vpc/v1/"+p+"/subnets/"+ids.Subnet, `"name":"fixture-subnet"`, `"status":"ACTIVE"`)
			expect("/vpc/v3/"+p+"/vpc/security-groups/"+ids.SecurityGroup, `"name":"fixture-sg"`, `"multiport":"22"`)
			expect("/ecs/v1/"+p+"/cloudservers/"+ids.Server, `"name":"fixture-server"`, `"status":"ACTIVE"`)
			expect("/rds/v3/"+p+"/instances?id="+ids.RDS, `"name":"fixture-mysql"`, `"status":"ACTIVE"`)

			_, body := inst.get(t, "/ims/v1/"+p+"/jobs/"+ids.ImageJob)
			var job struct {
				Status   string `json:"status"`
				Entities struct {
					ImageID string `json:"image_id"`
				} `json:"entities"`
			}
			if err := json.Unmarshal([]byte(body), &job); err != nil || job.Status != "SUCCESS" || job.Entities.ImageID == "" {
				t.Fatalf("image job: %s", body)
			}
			expect("/ims/v2/images/"+job.Entities.ImageID, `"name":"fixture-image"`, `"status":"active"`)

			owner := "OBS " + ids.BucketOwner + ":c2ln"
			status, object := inst.getAs(t, "/obs/"+ids.Bucket+"/"+ids.Object, owner)
			want := "written by WeiStack " + version
			if status != http.StatusOK || object != want {
				t.Fatalf("object: %d %q, want %q", status, object, want)
			}

			// Writing still works, and a new ID does not collide.
			res, err := http.Post("http://"+inst.addr+"/vpc/v1/"+p+"/vpcs", "application/json",
				strings.NewReader(`{"vpc": {"name": "after-upgrade", "cidr": "10.9.0.0/16"}}`))
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("creating a VPC after the upgrade: %d", res.StatusCode)
			}

			if err := inst.stop(t); err != nil {
				t.Fatalf("stopping: %v", err)
			}
			db, err := store.OpenBolt(filepath.Join(data, databaseFile))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if v, err := db.Format(); err != nil || v != store.FormatVersion {
				t.Fatalf("format after the upgrade = %d, %v", v, err)
			}
		})
	}
}

// TestNewerDataIsRefused: data from a future release is left alone, with
// a message saying why.
func TestNewerDataIsRefused(t *testing.T) {
	t.Parallel()
	data := copyFixture(t, filepath.Join("testdata", "upgrade", "v0.1.1", "data"))
	path := filepath.Join(data, databaseFile)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists([]byte("_weistack"))
		if err != nil {
			return err
		}
		value := make([]byte, 16, 18)
		binary.BigEndian.PutUint64(value[0:8], 1)
		binary.BigEndian.PutUint64(value[8:16], 99)
		return meta.Put([]byte("format"), append(value, "99"...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	err = Run(context.Background(), Env{
		Getenv: func(k string) string {
			return map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": data, "WEISTACK_PORT": "0", "WEISTACK_TLS_DIR": t.TempDir()}[k]
		},
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "newer WeiStack") || !strings.Contains(err.Error(), "format 99") {
		t.Fatalf("starting on newer data: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the newer file was modified")
	}
}
