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
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/victor-akande/weistack/internal/core/sigcheck"
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

	// From v0.3.0: identity, KMS, EIP, NAT, ELB and EVS data disks.
	User         string `json:"user"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	KMSKey       string `json:"kms_key"`
	CipherText   string `json:"cipher_text"`
	PlainText    string `json:"plain_text"`
	PublicIP     string `json:"public_ip"`
	NATGateway   string `json:"nat_gateway"`
	SNATRule     string `json:"snat_rule"`
	LoadBalancer string `json:"load_balancer"`
	Listener     string `json:"listener"`
	Pool         string `json:"pool"`
	Member       string `json:"member"`
	Volume       string `json:"volume"`
	Snapshot     string `json:"snapshot"`
}

// upgradeRehearsal names a data directory generate.sh wrote with a local
// binary (WEISTACK_FIXTURE_OUT/data), tested as one more release before a
// release's own fixture exists.
const upgradeRehearsal = "WEISTACK_UPGRADE_REHEARSAL"

// releaseFixtures lists every release's data directory, and the
// rehearsal's if one is named.
func releaseFixtures(t *testing.T) map[string]string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join("testdata", "upgrade", "v*", "data"))
	if err != nil || len(dirs) < 2 {
		t.Fatalf("release fixtures = %v, %v; want one per release", dirs, err)
	}
	fixtures := make(map[string]string, len(dirs)+1)
	for _, dir := range dirs {
		fixtures[filepath.Base(filepath.Dir(dir))] = dir
	}
	if dir := os.Getenv(upgradeRehearsal); dir != "" {
		fixtures["rehearsal"] = dir
	}
	return fixtures
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
	for version, dir := range releaseFixtures(t) {
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
			expect("/evs/v2/"+p+"/cloudvolumes/detail?server_id="+ids.Server, `"status":"in-use"`, `"bootable":"true"`)
			expect("/rds/v3/"+p+"/instances?id="+ids.RDS, `"name":"fixture-mysql"`, `"status":"ACTIVE"`)

			// The inventory reads every scope of the release's data, and its
			// records.
			expect("/_weistack/inventory", `"id":"`+ids.VPC+`"`, `"id":"`+ids.Subnet+`"`, `"id":"`+ids.SecurityGroup+`"`)
			expect("/_weistack/inventory?type=vpc.vpcs&id="+ids.VPC, `"count":1`, `"name":"fixture-vpc"`, `"provisioning_state":"Succeeded"`)

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
			if !strings.HasPrefix(object, "written by WeiStack v") {
				t.Fatalf("object: %d %q", status, object)
			}
			if want := "written by WeiStack " + version; version != "rehearsal" && (status != http.StatusOK || object != want) {
				t.Fatalf("object: %d %q, want %q", status, object, want)
			}

			if ids.User != "" {
				checkV03Resources(t, inst, p, ids)
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
			if v, err := db.Format(); err != nil || v != store.FormatVersion {
				t.Fatalf("format after the upgrade = %d, %v", v, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			if ids.AccessKey != "" {
				// The user's secret key is sealed by the vault key: under
				// -iam=enforce, a request it signs is still accepted.
				enforced := startInstance(t, map[string]string{"WEISTACK_PERSIST": "1", "WEISTACK_DATA_DIR": data, "WEISTACK_IAM": "enforce"})
				path := "/iam/v3/auth/projects"
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+enforced.addr+path, nil)
				sigcheck.SignSDKHMAC(req, ids.AccessKey, ids.SecretKey, path, nil, time.Now())
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if res.StatusCode != http.StatusOK || !strings.Contains(string(body), p) {
					t.Fatalf("signed by the release's access key: %d %s", res.StatusCode, body)
				}
				if err := enforced.stop(t); err != nil {
					t.Fatalf("stopping: %v", err)
				}
			}
		})
	}
}

// checkV03Resources reads back what v0.3.0 added to the fixture, and
// decrypts with the release's KMS key, whose material the vault key seals.
func checkV03Resources(t *testing.T, inst *instance, p string, ids fixtureIDs) {
	t.Helper()
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
	expect("/iam/v3.0/OS-USER/users/"+ids.User, `"name":"fixture-user"`)
	expect("/iam/v3.0/OS-CREDENTIAL/credentials/"+ids.AccessKey, `"status":"active"`)
	expect("/vpc/v1/"+p+"/publicips/"+ids.PublicIP, `"status":"ACTIVE"`)
	expect("/nat/v2/"+p+"/nat_gateways/"+ids.NATGateway, `"name":"fixture-nat"`, `"status":"ACTIVE"`)
	expect("/nat/v2/"+p+"/snat_rules/"+ids.SNATRule, `"floating_ip_id":"`+ids.PublicIP+`"`, `"status":"ACTIVE"`)
	expect("/elb/v3/"+p+"/elb/loadbalancers/"+ids.LoadBalancer, `"name":"fixture-lb"`, `"provisioning_status":"ACTIVE"`)
	expect("/elb/v3/"+p+"/elb/listeners/"+ids.Listener, `"name":"fixture-listener"`, `"default_pool_id":"`+ids.Pool+`"`)
	expect("/elb/v3/"+p+"/elb/pools/"+ids.Pool+"/members/"+ids.Member, `"protocol_port":8080`)
	expect("/evs/v2/"+p+"/cloudvolumes/"+ids.Volume, `"name":"fixture-data"`, `"status":"in-use"`)
	expect("/evs/v2/"+p+"/cloudsnapshots/"+ids.Snapshot, `"name":"fixture-snapshot"`, `"status":"available"`)

	body, err := json.Marshal(map[string]string{"key_id": ids.KMSKey, "cipher_text": ids.CipherText})
	if err != nil {
		t.Fatal(err)
	}
	status, out := inst.send(t, http.MethodPost, "/kms/v1.0/"+p+"/kms/decrypt-data", body)
	if status != http.StatusOK || !strings.Contains(out, `"plain_text":"`+ids.PlainText+`"`) {
		t.Fatalf("decrypting with the release's KMS key: %d %s", status, out)
	}

	invStatus, invBody := inst.get(t, "/_weistack/inventory")
	if invStatus != http.StatusOK {
		t.Fatalf("GET /_weistack/inventory: %d %s", invStatus, invBody)
	}
	type invRelation struct {
		FromResourceID string `json:"from_resource_id"`
		ToResourceID   string `json:"to_resource_id"`
	}
	var inv struct {
		Resources []struct {
			ID        string        `json:"id"`
			Relations []invRelation `json:"relations"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(invBody), &inv); err != nil {
		t.Fatalf("decoding inventory: %v\n%s", err, invBody)
	}
	seen := make(map[string]bool, len(inv.Resources))
	relationsByID := make(map[string][]invRelation, len(inv.Resources))
	for _, r := range inv.Resources {
		seen[r.ID] = true
		relationsByID[r.ID] = append(relationsByID[r.ID], r.Relations...)
	}
	for _, want := range []struct {
		label, id string
	}{
		{"PublicIP", ids.PublicIP},
		{"NATGateway", ids.NATGateway},
		{"SNATRule", ids.SNATRule},
		{"LoadBalancer", ids.LoadBalancer},
		{"Listener", ids.Listener},
		{"Pool", ids.Pool},
		{"Member", ids.Member},
		{"Volume", ids.Volume},
		{"Snapshot", ids.Snapshot},
		{"KMSKey", ids.KMSKey},
		{"User", ids.User},
	} {
		if !seen[want.id] {
			t.Errorf("inventory lacks %s %q", want.label, want.id)
		}
	}
	hasRelation := func(fromID, toID string) bool {
		for _, rel := range relationsByID[fromID] {
			if rel.FromResourceID == fromID && rel.ToResourceID == toID {
				return true
			}
		}
		return false
	}
	for _, want := range []struct {
		label, from, to string
	}{
		{"PublicIP -> NATGateway", ids.PublicIP, ids.NATGateway},
		{"Listener -> Pool", ids.Listener, ids.Pool},
		{"Member -> Pool", ids.Member, ids.Pool},
	} {
		if !hasRelation(want.from, want.to) {
			t.Errorf("inventory lacks relation %s (%s -> %s); got %+v",
				want.label, want.from, want.to, relationsByID[want.from])
		}
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
