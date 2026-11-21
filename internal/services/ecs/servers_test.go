package ecs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/evs"
	"github.com/victor-akande/weistack/internal/services/ims"
	"github.com/victor-akande/weistack/internal/services/vpc"
)

const (
	ubuntuImage  = "455b5860-f96d-5d89-baaa-ec6adb758c5b" // Ubuntu 22.04 server 64bit
	unknownID    = "00000000-0000-4000-8000-000000000000"
	serversPath  = "/v1/{project}/cloudservers"
	otherProject = "ffffffffffffffffffffffffffffffff"
)

// network is the VPC, subnet and security group a test server lives in.
type network struct {
	vpcID, subnetID, groupID string
}

// settle lets one lifecycle step complete.
func (e *env) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(testDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

// mustNetwork creates an active VPC, a /24 subnet in it and a security group.
func (e *env) mustNetwork(t *testing.T, tenant Tenant, cidr string) network {
	t.Helper()
	ctx := t.Context()
	vt := tenant.vpc()
	v, err := e.network.CreateVPC(ctx, vt, vpc.CreateVPCOption{CIDR: ptr("192.168.0.0/16")})
	if err != nil {
		t.Fatalf("CreateVPC: %v", err)
	}
	gateway := strings.TrimSuffix(cidr, "0/24") + "1"
	sn, err := e.network.CreateSubnet(ctx, vt, vpc.CreateSubnetOption{Name: "subnet", CIDR: cidr, GatewayIP: gateway, VPCID: v.ID})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	g, err := e.network.CreateSecurityGroup(ctx, vt, vpc.CreateSecurityGroupOption{Name: "web"}, false)
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	e.settle(t)
	return network{vpcID: v.ID, subnetID: sn.ID, groupID: g.ID}
}

// serverBody builds a create request. Each "key": value pair in extra
// replaces the default field of that name or is added.
func (n network) serverBody(extra ...string) string {
	fields := map[string]string{
		"name":        `"ecs-test"`,
		"imageRef":    `"` + ubuntuImage + `"`,
		"flavorRef":   `"s6.large.2"`,
		"vpcid":       `"` + n.vpcID + `"`,
		"nics":        `[{"subnet_id": "` + n.subnetID + `"}]`,
		"root_volume": `{"volumetype": "GPSSD"}`,
	}
	order := []string{"name", "imageRef", "flavorRef", "vpcid", "nics", "root_volume"}
	for i := 0; i+1 < len(extra); i += 2 {
		if _, known := fields[extra[i]]; !known {
			order = append(order, extra[i])
		}
		fields[extra[i]] = extra[i+1]
	}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		if fields[k] != "<omit>" {
			parts = append(parts, fmt.Sprintf("%q: %s", k, fields[k]))
		}
	}
	return `{"server": {` + strings.Join(parts, ", ") + `}}`
}

// mustCreate creates servers over HTTP and returns the job and server IDs.
func (e *env) mustCreate(t *testing.T, body string) (string, []string) {
	t.Helper()
	status, out := e.call(t, http.MethodPost, serversPath, body)
	if status != http.StatusOK {
		t.Fatalf("creating servers: %d %s", status, out)
	}
	res := decodeInto[createServersResponse](t, out)
	return res.JobID, res.ServerIDs
}

func (e *env) server(t *testing.T, id string) Server {
	t.Helper()
	srv, err := e.svc.GetServer(t.Context(), testTenant, id)
	if err != nil {
		t.Fatalf("GetServer(%s): %v", id, err)
	}
	return srv
}

func (e *env) subnetFree(t *testing.T, id string) int {
	t.Helper()
	sn, err := e.network.GetSubnet(t.Context(), testTenant.vpc(), id)
	if err != nil {
		t.Fatal(err)
	}
	return sn.AvailableIPAddressCount
}

func codeOf(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestServerLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	jobPath := func(id string) string { return "/v1/{project}/jobs/" + id }

	e.expect(t, "list_servers_empty", http.MethodGet, serversPath+"/detail", "")

	out := e.expect(t, "create_servers", http.MethodPost, serversPath, n.serverBody())
	created := decodeInto[createServersResponse](t, out)
	id := created.ServerIDs[0]

	e.expect(t, "show_server_build", http.MethodGet, serversPath+"/"+id, "")
	e.expect(t, "show_job_create_running", http.MethodGet, jobPath(created.JobID), "")

	e.settle(t)
	e.expect(t, "show_server_active", http.MethodGet, serversPath+"/"+id, "")
	e.expect(t, "show_job_create_success", http.MethodGet, jobPath(created.JobID), "")
	e.expect(t, "list_servers", http.MethodGet, serversPath+"/detail", "")

	if free := e.subnetFree(t, n.subnetID); free != 250 {
		t.Errorf("subnet has %d free addresses, want 250 after one server", free)
	}

	out = e.expect(t, "delete_servers", http.MethodPost, serversPath+"/delete",
		`{"servers": [{"id": "`+id+`"}], "delete_publicip": true, "delete_volume": true}`)
	deleteJob := decodeInto[jobResponse](t, out).JobID
	e.expect(t, "show_server_deleting", http.MethodGet, serversPath+"/"+id, "")

	e.settle(t)
	e.expect(t, "error_ecs_0114", http.MethodGet, serversPath+"/"+id, "")
	e.expect(t, "show_job_delete_success", http.MethodGet, jobPath(deleteJob), "")
	e.expect(t, "list_servers_empty", http.MethodGet, serversPath+"/detail", "")

	// Its address is free again, and the network can be torn down.
	if free := e.subnetFree(t, n.subnetID); free != 251 {
		t.Errorf("subnet has %d free addresses, want 251 after the delete", free)
	}
	if err := e.network.DeleteSubnet(t.Context(), testTenant.vpc(), n.vpcID, n.subnetID); err != nil {
		t.Errorf("deleting the subnet after its server: %v", err)
	}

	e.expect(t, "error_common_0011", http.MethodGet, jobPath(strings.Repeat("0", 32)), "")
}

// The same request body is accepted on the v1.1 path, which Terraform uses.
func TestCreateOnV11Path(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	e.expect(t, "create_servers", http.MethodPost, "/v1.1/{project}/cloudservers", n.serverBody())
}

func TestCreateServerValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	other := e.mustNetwork(t, testTenant, "192.168.2.0/24")

	// A private image that is not active yet, and one in another project.
	queued := ims.Image{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Name: "queued", Status: ims.StatusQueued, MinDisk: 40, Tags: []string{}}
	if err := store.Of[ims.Image](e.store, store.Scope{Region: testRegion, ProjectID: testProject, Kind: "ims.image"}).Create(t.Context(), queued.ID, queued); err != nil {
		t.Fatal(err)
	}
	armImage := "" // the ARM public image
	imgs, _ := e.images.ListImages(t.Context(), testTenant.ims(), ims.ListImagesFilter{Name: "Huawei Cloud EulerOS 2.0 Standard 64 bit for kAi2p"})
	armImage = imgs[0].ID

	tags := func(n int) string {
		var parts []string
		for i := range n {
			parts = append(parts, fmt.Sprintf(`{"key": "k%d", "value": "v"}`, i))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	volumes := func(n int) string {
		return "[" + strings.TrimSuffix(strings.Repeat(`{"volumetype": "SAS", "size": 10},`, n), ",") + "]"
	}
	nics := func(n int) string {
		return "[" + strings.TrimSuffix(strings.Repeat(`{"subnet_id": "`+unknownID+`"},`, n), ",") + "]"
	}

	tests := []struct{ name, body, golden string }{
		{"empty body", ``, "error_ecs_0005"},
		{"malformed", `{"server": `, "error_ecs_0005"},
		{"missing server object", `{}`, "error_ecs_0005"},
		{"dry run", `{"dry_run": true, "server": {}}`, "error_not_implemented"},
		{"missing name", n.serverBody("name", "<omit>"), "error_ecs_0915"},
		{"name with space", n.serverBody("name", `"my server"`), "error_ecs_0915"},
		{"name too long", n.serverBody("name", `"`+strings.Repeat("n", 65)+`"`), "error_ecs_0914"},
		{"long description", n.serverBody("description", `"`+strings.Repeat("d", 86)+`"`), "error_ecs_0005"},
		{"count zero", n.serverBody("count", `0`), "error_ecs_0005"},
		{"count too large", n.serverBody("count", `501`), "error_ecs_0913"},
		{"short password", n.serverBody("adminPass", `"Ab1!"`), "error_ecs_0011"},
		{"simple password", n.serverBody("adminPass", `"alllowercase"`), "error_ecs_0011"},
		{"password with space", n.serverBody("adminPass", `"Passw0rd with space"`), "error_ecs_0011"},
		{"missing flavor", n.serverBody("flavorRef", "<omit>"), "error_ecs_0005"},
		{"unknown flavor", n.serverBody("flavorRef", `"z9.huge.1"`), "error_ecs_0029"},
		{"missing image", n.serverBody("imageRef", "<omit>"), "error_ecs_0005"},
		{"unknown image", n.serverBody("imageRef", `"`+unknownID+`"`), "error_ecs_0031"},
		{"image not active", n.serverBody("imageRef", `"`+queued.ID+`"`), "error_ecs_0032"},
		{"arm image on x86 flavor", n.serverBody("imageRef", `"`+armImage+`"`), "error_ecs_0007"},
		{"x86 image on arm flavor", n.serverBody("flavorRef", `"kc1.large.2"`), "error_ecs_0007"},
		{"unknown zone", n.serverBody("availability_zone", `"cn-north-4a"`), "error_ecs_0005"},
		{"missing root volume", n.serverBody("root_volume", "<omit>"), "error_ecs_0005"},
		{"unknown disk type", n.serverBody("root_volume", `{"volumetype": "FLOPPY"}`), "error_ecs_0043"},
		{"root disk below image minimum", n.serverBody("root_volume", `{"volumetype": "SSD", "size": 20}`), "error_ecs_0005"},
		{"root disk too large", n.serverBody("root_volume", `{"volumetype": "SSD", "size": 2000}`), "error_ecs_0005"},
		{"too many data disks", n.serverBody("data_volumes", volumes(24)), "error_ecs_0042"},
		{"data disk type", n.serverBody("data_volumes", `[{"volumetype": "TAPE", "size": 100}]`), "error_ecs_0043"},
		{"data disk without size", n.serverBody("data_volumes", `[{"volumetype": "SAS"}]`), "error_ecs_0005"},
		{"data disk too small", n.serverBody("data_volumes", `[{"volumetype": "SAS", "size": 5}]`), "error_ecs_0005"},
		{"missing vpc", n.serverBody("vpcid", "<omit>"), "error_ecs_0005"},
		{"unknown vpc", n.serverBody("vpcid", `"`+unknownID+`"`), "error_ecs_0014"},
		{"no nics", n.serverBody("nics", `[]`), "error_ecs_0005"},
		{"too many nics", n.serverBody("nics", nics(13)), "error_ecs_0050"},
		{"nic without subnet", n.serverBody("nics", `[{}]`), "error_ecs_0005"},
		{"unknown subnet", n.serverBody("nics", `[{"subnet_id": "`+unknownID+`"}]`), "error_ecs_0038"},
		{"subnet of another vpc", n.serverBody("nics", `[{"subnet_id": "`+other.subnetID+`"}]`), "error_ecs_0064"},
		{"subnet used twice", n.serverBody("nics", `[{"subnet_id": "`+n.subnetID+`"}, {"subnet_id": "`+n.subnetID+`"}]`), "error_ecs_0005"},
		{"fixed ip with count", n.serverBody("count", `2`, "nics", `[{"subnet_id": "`+n.subnetID+`", "ip_address": "192.168.1.9"}]`), "error_ecs_0005"},
		{"ip outside subnet", n.serverBody("nics", `[{"subnet_id": "`+n.subnetID+`", "ip_address": "10.0.0.5"}]`), "error_ecs_0039"},
		{"ip is the gateway", n.serverBody("nics", `[{"subnet_id": "`+n.subnetID+`", "ip_address": "192.168.1.1"}]`), "error_ecs_0039"},
		{"unknown security group", n.serverBody("security_groups", `[{"id": "`+unknownID+`"}]`), "error_ecs_0014"},
		{"bad enterprise project", n.serverBody("extendparam", `{"enterprise_project_id": "x"}`), "error_ecs_0005"},
		{"too many tags", n.serverBody("server_tags", tags(11)), "error_ecs_0905"},
		{"empty tag key", n.serverBody("server_tags", `[{"key": "", "value": "v"}]`), "error_ecs_0906"},
		{"both tag forms", n.serverBody("server_tags", `[{"key": "a", "value": "1"}]`, "tags", `["b.2"]`), "error_ecs_0906"},
		{"tag with bad character", n.serverBody("server_tags", `[{"key": "a*b", "value": "v"}]`), "error_ecs_0907"},
		{"duplicate tag key", n.serverBody("server_tags", `[{"key": "a", "value": "1"}, {"key": "a", "value": "2"}]`), "error_ecs_0908"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, serversPath, tt.body)
		})
	}

	// Nothing was created and no address was consumed.
	all, _ := e.svc.ListServers(t.Context(), testTenant, ListServersFilter{})
	if len(all) != 0 {
		t.Errorf("%d servers exist after rejected requests", len(all))
	}
	if free := e.subnetFree(t, n.subnetID); free != 251 {
		t.Errorf("rejected requests consumed addresses: %d free, want 251", free)
	}
}

func TestCreateServerOptions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	_, ids := e.mustCreate(t, n.serverBody(
		"name", `"web.prod_1"`,
		"description", `"front end"`,
		"availability_zone", `"ap-southeast-1b"`,
		"nics", `[{"subnet_id": "`+n.subnetID+`", "ip_address": "192.168.1.50"}]`,
		"security_groups", `[{"id": "`+n.groupID+`"}, {"id": "`+n.groupID+`"}]`,
		"root_volume", `{"volumetype": "SSD", "size": 80}`,
		"data_volumes", `[{"volumetype": "SAS", "size": 100}, {"volumetype": "GPSSD", "size": 200}]`,
		"adminPass", `"Str0ng!Passw0rd"`,
		"key_name", `"my-key"`,
		"user_data", `"IyEvYmluL2Jhc2g="`,
		"metadata", `{"role": "web", "os_type": "ignored-by-nobody"}`,
		"server_tags", `[{"key": "env", "value": "prod"}, {"key": "team", "value": ""}]`,
		"publicip", `{"eip": {"iptype": "5_bgp", "bandwidth": {"size": 5, "sharetype": "PER"}}}`,
		"extendparam", `{"enterprise_project_id": "0aad99bc-f5f6-4f78-8404-c598d76b0ed2"}`,
	))
	e.settle(t)

	status, out := e.call(t, http.MethodGet, serversPath+"/"+ids[0], "")
	if status != http.StatusOK {
		t.Fatalf("show: %d %s", status, out)
	}
	d := decodeInto[serverResponse](t, out).Server

	addrs := d.Addresses[n.vpcID]
	if len(addrs) != 2 || addrs[0].Addr != "192.168.1.50" || addrs[0].Type != "fixed" || !addrs[0].Primary ||
		addrs[1].Type != "floating" || addrs[1].Addr != "192.0.2.1" || addrs[1].Primary ||
		addrs[1].PortID != addrs[0].PortID || addrs[1].MACAddr != addrs[0].MACAddr {
		t.Errorf("addresses = %+v", addrs)
	}
	if !strings.HasPrefix(addrs[0].MACAddr, "fa:16:3e:") || len(addrs[0].MACAddr) != 17 {
		t.Errorf("MAC = %q", addrs[0].MACAddr)
	}
	if len(d.SecurityGroups) != 1 || d.SecurityGroups[0].ID != n.groupID || d.SecurityGroups[0].Name != "web" {
		t.Errorf("security groups = %+v (a repeated group must appear once)", d.SecurityGroups)
	}
	if len(d.VolumesAttached) != 3 || d.VolumesAttached[1].Device != "/dev/vdb" || d.VolumesAttached[2].Device != "/dev/vdc" ||
		d.VolumesAttached[1].BootIndex != "-1" {
		t.Errorf("volumes = %+v", d.VolumesAttached)
	}
	if d.Name != "web.prod_1" || d.Description != "front end" || d.AvailabilityZone != "ap-southeast-1b" ||
		d.KeyName == nil || *d.KeyName != "my-key" || d.UserData == nil || *d.UserData != "IyEvYmluL2Jhc2g=" ||
		d.EnterpriseProject == "0" || d.SysTags[0].Value != d.EnterpriseProject {
		t.Errorf("detail = %+v", d)
	}
	if strings.Join(d.Tags, ",") != "env=prod,team" {
		t.Errorf("tags = %v", d.Tags)
	}
	// User metadata is merged over the system keys.
	if d.Metadata["role"] != "web" || d.Metadata["os_type"] != "ignored-by-nobody" || d.Metadata["vpc_id"] != n.vpcID {
		t.Errorf("metadata = %v", d.Metadata)
	}

	// The password is never stored or returned.
	raw, _ := json.Marshal(e.server(t, ids[0]))
	if strings.Contains(string(raw), "Str0ng") || strings.Contains(string(out), "Str0ng") {
		t.Error("the admin password leaked into stored state or a response")
	}
	if disks, err := e.volumes.DisksOf(t.Context(), testTenant.evs(), ids[0]); err != nil || len(disks) == 0 || disks[0].SizeGB != 80 || disks[0].Type != "SSD" {
		t.Errorf("root volume = %+v, %v", disks, err)
	}

	// That address is now taken.
	e.expect(t, "error_ecs_0010", http.MethodPost, serversPath,
		n.serverBody("nics", `[{"subnet_id": "`+n.subnetID+`", "ip_address": "192.168.1.50"}]`))

	// The older "tags" form, and the default security group when none is given.
	_, ids = e.mustCreate(t, n.serverBody("tags", `["a.1", "b"]`))
	srv := e.server(t, ids[0])
	if strings.Join(srv.Tags, ",") != "a=1,b" {
		t.Errorf("tags = %v", srv.Tags)
	}
	g, err := e.network.GetSecurityGroup(t.Context(), testTenant.vpc(), srv.SecurityGroups[0])
	if err != nil || g.Name != "default" || len(srv.SecurityGroups) != 1 {
		t.Errorf("default security group: %+v, %v", srv.SecurityGroups, err)
	}
	if srv.AvailabilityZone != "ap-southeast-1a" {
		t.Errorf("default zone = %q", srv.AvailabilityZone)
	}
}

func TestCreateSeveralServers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	jobID, ids := e.mustCreate(t, n.serverBody("name", `"node"`, "count", `3`))
	if len(ids) != 3 {
		t.Fatalf("%d server IDs, want 3", len(ids))
	}
	seenIP := map[string]bool{}
	for i, id := range ids {
		srv := e.server(t, id)
		if want := fmt.Sprintf("node-%04d", i+1); srv.Name != want || srv.LaunchIndex != i {
			t.Errorf("server %d: name %q index %d, want %q", i, srv.Name, srv.LaunchIndex, want)
		}
		if seenIP[srv.NICs[0].IP] {
			t.Errorf("address %s given to two servers", srv.NICs[0].IP)
		}
		seenIP[srv.NICs[0].IP] = true
		if srv.ReservationID != e.server(t, ids[0]).ReservationID {
			t.Error("servers of one request have different reservation IDs")
		}
	}

	job, _ := e.svc.GetJob(t.Context(), testTenant, jobID)
	if job.Status != JobRunning || job.Entities.SubJobsTotal != 3 || len(job.Entities.SubJobs) != 3 {
		t.Fatalf("job = %+v", job)
	}
	e.settle(t)
	job, _ = e.svc.GetJob(t.Context(), testTenant, jobID)
	if job.Status != JobSuccess || job.EndTime == "" {
		t.Fatalf("job after build = %+v", job)
	}
	for _, sub := range job.Entities.SubJobs {
		if sub.Status != JobSuccess || sub.JobType != jobCreateSingleServer {
			t.Errorf("sub-job = %+v", sub)
		}
	}

	// Batch delete of all three.
	body := `{"servers": [{"id": "` + strings.Join(ids, `"}, {"id": "`) + `"}]}`
	status, out := e.call(t, http.MethodPost, serversPath+"/delete", body)
	if status != http.StatusOK {
		t.Fatalf("delete: %d %s", status, out)
	}
	e.settle(t)
	if all, _ := e.svc.ListServers(t.Context(), testTenant, ListServersFilter{}); len(all) != 0 {
		t.Errorf("%d servers remain", len(all))
	}
	if free := e.subnetFree(t, n.subnetID); free != 251 {
		t.Errorf("%d free addresses, want 251", free)
	}
}

func TestDeleteValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	_, ids := e.mustCreate(t, n.serverBody())
	e.settle(t)
	del := func(ids ...string) string {
		return `{"servers": [{"id": "` + strings.Join(ids, `"}, {"id": "`) + `"}]}`
	}

	e.expect(t, "error_ecs_0005", http.MethodPost, serversPath+"/delete", ``)
	e.expect(t, "error_ecs_0005", http.MethodPost, serversPath+"/delete", `{"servers": []}`)
	e.expect(t, "error_ecs_0005", http.MethodPost, serversPath+"/delete", del(ids[0], ids[0]))
	e.expect(t, "error_ecs_0114", http.MethodPost, serversPath+"/delete", del(unknownID))
	// One unknown server rejects the whole batch.
	e.expect(t, "error_ecs_0114", http.MethodPost, serversPath+"/delete", del(ids[0], unknownID))
	if srv := e.server(t, ids[0]); srv.TaskState != "" {
		t.Fatalf("a rejected batch touched the server: task_state %q", srv.TaskState)
	}
}

func TestDeleteWhileBuildingCancelsTheBuild(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	createJob, ids := e.mustCreate(t, n.serverBody())
	del, err := e.svc.DeleteServers(t.Context(), testTenant, ids)
	if err != nil {
		t.Fatalf("deleting a BUILD server: %v", err)
	}
	// The create job fails at once: its work was abandoned.
	if job, _ := e.svc.GetJob(t.Context(), testTenant, createJob); job.Status != JobFail {
		t.Errorf("create job status = %q, want FAIL", job.Status)
	}
	e.settle(t)
	if _, err := e.svc.GetServer(t.Context(), testTenant, ids[0]); codeOf(err) != "Ecs.0114" {
		t.Errorf("server after delete: %v", err)
	}
	if job, _ := e.svc.GetJob(t.Context(), testTenant, del.JobID); job.Status != JobSuccess {
		t.Errorf("delete job status = %q", job.Status)
	}
	if n := e.engine.Pending(); n != 0 {
		t.Errorf("%d lifecycle tasks left", n)
	}
}

func TestQuotas(t *testing.T) {
	t.Parallel()
	e := newEnvFull(t, store.NewMemory(), "", Quota{Servers: 3, VCPUs: 8})
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	e.mustCreate(t, n.serverBody("count", `2`))                                                              // 2 servers, 4 vCPUs
	e.expect(t, "error_ecs_0001", http.MethodPost, serversPath, n.serverBody("count", `2`))                  // 4 servers
	e.expect(t, "error_ecs_0001", http.MethodPost, serversPath, n.serverBody("flavorRef", `"s6.2xlarge.2"`)) // 12 vCPUs
	_, ids := e.mustCreate(t, n.serverBody("flavorRef", `"s6.xlarge.2"`))                                    // 3 servers, 8 vCPUs
	e.expect(t, "error_ecs_0001", http.MethodPost, serversPath, n.serverBody("flavorRef", `"s6.small.1"`))

	// Quota is per project.
	on := e.mustNetwork(t, Tenant{Region: testRegion, ProjectID: otherProject}, "192.168.1.0/24")
	if _, _, err := e.svc.CreateServers(t.Context(), Tenant{Region: testRegion, ProjectID: otherProject}, CreateServerOption{
		Name: "x", ImageRef: ubuntuImage, FlavorRef: "s6.large.2", VPCID: on.vpcID,
		NICs: []CreateNIC{{SubnetID: on.subnetID}}, RootVolume: &CreateVolume{VolumeType: "SSD"},
	}); err != nil {
		t.Errorf("another project is blocked by this project's quota: %v", err)
	}

	// Deleting frees quota.
	if _, err := e.svc.DeleteServers(t.Context(), testTenant, ids); err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	e.mustCreate(t, n.serverBody("flavorRef", `"s6.small.1"`))
}

func TestSubnetExhaustionRollsBack(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	v, _ := e.network.CreateVPC(ctx, testTenant.vpc(), vpc.CreateVPCOption{CIDR: ptr("10.0.0.0/8")})
	tiny, err := e.network.CreateSubnet(ctx, testTenant.vpc(), vpc.CreateSubnetOption{Name: "tiny", CIDR: "10.0.0.0/29", GatewayIP: "10.0.0.1", VPCID: v.ID})
	if err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	n := network{vpcID: v.ID, subnetID: tiny.ID}

	// Three usable addresses: asking for four must take none.
	e.expect(t, "error_ecs_0012", http.MethodPost, serversPath, n.serverBody("count", `4`))
	if free := e.subnetFree(t, tiny.ID); free != 3 {
		t.Fatalf("a failed create kept addresses: %d free, want 3", free)
	}
	if all, _ := e.svc.ListServers(ctx, testTenant, ListServersFilter{}); len(all) != 0 {
		t.Fatalf("a failed create left %d servers", len(all))
	}
	e.mustCreate(t, n.serverBody("count", `3`))
	e.expect(t, "error_ecs_0012", http.MethodPost, serversPath, n.serverBody())
}

func TestListServersFiltersAndPaging(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	e.mustCreate(t, n.serverBody("name", `"web-1"`, "server_tags", `[{"key": "env", "value": "prod"}, {"key": "tier", "value": "web"}]`))
	e.mustCreate(t, n.serverBody("name", `"web-2"`, "flavorRef", `"c7.large.2"`, "server_tags", `[{"key": "env", "value": "dev"}]`))
	e.settle(t)
	_, building := e.mustCreate(t, n.serverBody("name", `"db-1"`, "nics", `[{"subnet_id": "`+n.subnetID+`", "ip_address": "192.168.1.200"}]`))

	list := func(query string) (string, int) {
		t.Helper()
		status, out := e.call(t, http.MethodGet, serversPath+"/detail"+query, "")
		if status != http.StatusOK {
			t.Fatalf("list %s: %d %s", query, status, out)
		}
		res := decodeInto[listServersResponse](t, out)
		var names []string
		for _, s := range res.Servers {
			names = append(names, s.Name)
		}
		return strings.Join(names, ","), res.Count
	}

	tests := []struct {
		query     string
		want      string
		wantCount int
	}{
		{"", "web-1,web-2,db-1", 3},
		{"?name=web", "web-1,web-2", 2},
		{"?name=b-1", "web-1,db-1", 2},
		{"?status=ACTIVE", "web-1,web-2", 2},
		{"?status=BUILD", "db-1", 1},
		{"?flavor=c7.large.2", "web-2", 1},
		{"?ip=192.168.1.2", "web-1,db-1", 2}, // prefix: .2 and .200
		{"?ip_eq=192.168.1.2", "web-1", 1},
		{"?server_id=" + building[0], "db-1", 1},
		{"?tags=env", "web-1,web-2", 2},
		{"?tags=env%3Dprod", "web-1", 1},
		{"?tags=env%3Dprod,tier%3Dweb", "web-1", 1},
		{"?tags=env%3Dprod,tier%3Ddb", "", 0},
		{"?not-tags=env", "db-1", 1},
		{"?enterprise_project_id=0", "web-1,web-2,db-1", 3},
		{"?enterprise_project_id=all_granted_eps", "web-1,web-2,db-1", 3},
		{"?reservation_id=r-nope", "", 0},
		// offset is a page number starting at 1; count is always the total.
		{"?limit=2", "web-1,web-2", 3},
		{"?limit=2&offset=1", "web-1,web-2", 3},
		{"?limit=2&offset=0", "web-1,web-2", 3},
		{"?limit=2&offset=2", "db-1", 3},
		{"?limit=2&offset=3", "", 3},
	}
	for _, tt := range tests {
		got, count := list(tt.query)
		if got != tt.want || count != tt.wantCount {
			t.Errorf("list %q = %q (count %d), want %q (count %d)", tt.query, got, count, tt.want, tt.wantCount)
		}
	}
	for _, bad := range []string{"?limit=0", "?limit=1001", "?limit=x", "?offset=-1", "?offset=x"} {
		e.expect(t, "error_ecs_0005", http.MethodGet, serversPath+"/detail"+bad, "")
	}

	// Servers are invisible to other projects.
	status, out := e.call(t, http.MethodGet, "/v1/"+otherProject+"/cloudservers/detail", "")
	if status != 200 || decodeInto[listServersResponse](t, out).Count != 0 {
		t.Errorf("another project lists servers: %s", out)
	}
	if status, _ := e.call(t, http.MethodGet, "/v1/"+otherProject+"/cloudservers/"+building[0], ""); status != http.StatusNotFound {
		t.Errorf("another project can show the server: %d", status)
	}
}

type failKind string

func (f failKind) Fault(kind, _ string) error {
	if kind == string(f) {
		return errors.New("injected hypervisor failure")
	}
	return nil
}

func TestBuildFaultLeavesServerInError(t *testing.T) {
	t.Parallel()
	e := newEnvFaulty(t, failKind(taskServerBuild))
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	jobID, ids := e.mustCreate(t, n.serverBody("count", `2`))
	e.settle(t)
	for _, id := range ids {
		if srv := e.server(t, id); srv.Status != StatusError || srv.TaskState != "" || srv.LaunchedAt != "" {
			t.Errorf("server = %+v, want status ERROR", srv)
		}
	}
	job, _ := e.svc.GetJob(t.Context(), testTenant, jobID)
	if job.Status != JobFail || job.ErrorCode == nil || *job.ErrorCode != "Ecs.0000" || job.FailReason == nil {
		t.Fatalf("job = %+v", job)
	}
	sub := job.Entities.SubJobs[0]
	if sub.Status != JobFail || sub.FailReason == nil || !strings.Contains(*sub.FailReason, "injected") {
		t.Fatalf("sub-job = %+v", sub)
	}
	// An ERROR server can still be listed by status and deleted.
	if all, _ := e.svc.ListServers(t.Context(), testTenant, ListServersFilter{Status: StatusError}); len(all) != 2 {
		t.Errorf("%d servers in ERROR", len(all))
	}
}

func TestDeleteFaultKeepsTheServer(t *testing.T) {
	t.Parallel()
	e := newEnvFaulty(t, failKind(taskServerDelete))
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	_, ids := e.mustCreate(t, n.serverBody())
	e.settle(t)

	job, err := e.svc.DeleteServers(t.Context(), testTenant, ids)
	if err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	if srv := e.server(t, ids[0]); srv.Status != StatusError || srv.TaskState != "" {
		t.Errorf("server after a failed delete = %+v", srv)
	}
	if got, _ := e.svc.GetJob(t.Context(), testTenant, job.JobID); got.Status != JobFail {
		t.Errorf("job status = %q", got.Status)
	}
	if free := e.subnetFree(t, n.subnetID); free != 250 {
		t.Errorf("a failed delete released the address: %d free", free)
	}
}

// Concurrent creates must never exceed the quota or share an address.
func TestConcurrentCreatesRespectQuotaAndAddresses(t *testing.T) {
	t.Parallel()
	e := newEnvFull(t, store.NewMemory(), "", Quota{Servers: 10, VCPUs: 1000})
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	opt := CreateServerOption{
		Name: "racer", ImageRef: ubuntuImage, FlavorRef: "s6.small.1", VPCID: n.vpcID,
		NICs: []CreateNIC{{SubnetID: n.subnetID}}, RootVolume: &CreateVolume{VolumeType: "SSD"},
	}

	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		ok, rejected int
	)
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := e.svc.CreateServers(t.Context(), testTenant, opt)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case codeOf(err) == "Ecs.0001":
				rejected++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 10 || rejected != 20 {
		t.Fatalf("%d created and %d rejected, want 10 and 20", ok, rejected)
	}
	all, _ := e.svc.ListServers(t.Context(), testTenant, ListServersFilter{})
	ips := map[string]bool{}
	for _, srv := range all {
		ips[srv.NICs[0].IP] = true
	}
	if len(all) != 10 || len(ips) != 10 {
		t.Fatalf("%d servers with %d distinct addresses, want 10 and 10", len(all), len(ips))
	}
	if free := e.subnetFree(t, n.subnetID); free != 241 {
		t.Fatalf("%d free addresses, want 241", free)
	}
}

// End-to-end scenario 2: make a private image of a server, then launch a
// second server from that image.
func TestImageFromServerAndServerFromImage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")
	_, ids := e.mustCreate(t, n.serverBody("root_volume", `{"volumetype": "SSD", "size": 60}`))
	e.settle(t)

	job, err := e.images.CreateImage(t.Context(), testTenant.ims(), ims.CreateImageOption{Name: "golden", InstanceID: ids[0]})
	if err != nil {
		t.Fatalf("CreateImage from the server: %v", err)
	}
	imageID := job.Entities.ImageID

	// Not usable until it is active.
	e.expect(t, "error_ecs_0032", http.MethodPost, serversPath, n.serverBody("imageRef", `"`+imageID+`"`))
	e.settle(t)
	e.settle(t)

	img, err := e.images.GetImage(t.Context(), testTenant.ims(), imageID)
	if err != nil || img.Status != ims.StatusActive || img.Platform != "Ubuntu" || img.MinDisk != 60 {
		t.Fatalf("image = %+v, %v; want an active Ubuntu image with min_disk 60", img, err)
	}

	// A root disk smaller than the image's is refused; the default fits.
	e.expect(t, "error_ecs_0005", http.MethodPost, serversPath, n.serverBody("imageRef", `"`+imageID+`"`, "root_volume", `{"volumetype": "SSD", "size": 40}`))
	_, second := e.mustCreate(t, n.serverBody("name", `"clone"`, "imageRef", `"`+imageID+`"`))
	e.settle(t)
	srv := e.server(t, second[0])
	disks, err := e.volumes.DisksOf(t.Context(), testTenant.evs(), second[0])
	if err != nil || len(disks) == 0 || srv.Status != StatusActive || srv.ImageID != imageID || srv.ImageType != "private" || disks[0].SizeGB != 60 {
		t.Fatalf("second server = %+v, disks = %+v, err = %v", srv, disks, err)
	}

	// Another project cannot image this server or boot from this image.
	if _, err := e.images.CreateImage(t.Context(), ims.Tenant{Region: testRegion, ProjectID: otherProject}, ims.CreateImageOption{Name: "stolen", InstanceID: ids[0]}); err == nil {
		t.Error("another project made an image of the server")
	}
}

func TestResumeContinuesInterruptedJobs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := newEnvWith(t, st, "")
	n := first.mustNetwork(t, testTenant, "192.168.1.0/24")

	_, done := first.mustCreate(t, n.serverBody("name", `"done"`))
	first.settle(t)
	_, doomed := first.mustCreate(t, n.serverBody("name", `"doomed"`))
	first.settle(t)
	// A delete and a create that the "crash" interrupts midway.
	delJob, err := first.svc.DeleteServers(t.Context(), testTenant, doomed)
	if err != nil {
		t.Fatal(err)
	}
	buildJob, building := first.mustCreate(t, n.serverBody("name", `"building"`))
	// A job whose server vanished behind its back.
	orphanJob, orphan := first.mustCreate(t, n.serverBody("name", `"orphan"`))
	if err := first.svc.servers(testTenant).Delete(t.Context(), orphan[0]); err != nil {
		t.Fatal(err)
	}
	first.engine.CancelAll()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, st, "")
	if err := e.svc.Resume(t.Context()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	e.settle(t)

	if srv := e.server(t, done[0]); srv.Status != StatusActive {
		t.Errorf("finished server changed: %+v", srv)
	}
	if srv := e.server(t, building[0]); srv.Status != StatusActive {
		t.Errorf("interrupted build: status %q, want ACTIVE", srv.Status)
	}
	if got, _ := e.svc.GetJob(t.Context(), testTenant, buildJob); got.Status != JobSuccess {
		t.Errorf("interrupted build job: %q", got.Status)
	}
	if _, err := e.svc.GetServer(t.Context(), testTenant, doomed[0]); codeOf(err) != "Ecs.0114" {
		t.Errorf("interrupted delete did not finish: %v", err)
	}
	if got, _ := e.svc.GetJob(t.Context(), testTenant, delJob.JobID); got.Status != JobSuccess {
		t.Errorf("interrupted delete job: %q", got.Status)
	}
	if got, _ := e.svc.GetJob(t.Context(), testTenant, orphanJob); got.Status != JobFail {
		t.Errorf("job of a vanished server: %q, want FAIL", got.Status)
	}

	scope := store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindJob}
	if _, err := e.store.Put(t.Context(), scope, "bad", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Resume(t.Context()); err == nil {
		t.Fatal("Resume ignored a corrupt job record")
	}
}

func TestServerPublicIPEndToEnd(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	// 1. Create server with PER EIP (delete_on_termination: false).
	_, ids := e.mustCreate(t, n.serverBody(
		"name", `"web-eip"`,
		"publicip", `{"eip": {"iptype": "5_bgp", "bandwidth": {"size": 5, "sharetype": "PER", "chargemode": "traffic"}}, "delete_on_termination": false}`,
	))
	e.settle(t)

	status, out := e.call(t, http.MethodGet, serversPath+"/"+ids[0], "")
	if status != http.StatusOK {
		t.Fatalf("show server: %d %s", status, out)
	}
	detail := decodeInto[serverResponse](t, out).Server
	addrs := detail.Addresses[n.vpcID]
	if len(addrs) != 2 || addrs[1].Type != "floating" || addrs[1].Addr != "192.0.2.1" || addrs[1].PortID != addrs[0].PortID {
		t.Fatalf("addresses = %+v, want floating 192.0.2.1 on primary port", addrs)
	}

	// Verify real EIP and PER bandwidth naming via the EIP v1 API.
	type pipItem struct {
		ID                 string `json:"id"`
		Status             string `json:"status"`
		PublicIPAddress    string `json:"public_ip_address"`
		PortID             string `json:"port_id"`
		PrivateIPAddress   string `json:"private_ip_address"`
		BandwidthName      string `json:"bandwidth_name"`
		BandwidthSize      int    `json:"bandwidth_size"`
		BandwidthShareType string `json:"bandwidth_share_type"`
	}
	type pipListResp struct {
		PublicIPs []pipItem `json:"publicips"`
	}
	status, out = e.callVPC(t, http.MethodGet, "/v1/{project}/publicips", "")
	if status != http.StatusOK {
		t.Fatalf("list publicips: %d %s", status, out)
	}
	pips := decodeInto[pipListResp](t, out).PublicIPs
	if len(pips) != 1 {
		t.Fatalf("publicips = %+v, want 1", pips)
	}
	eipID := pips[0].ID
	wantBW := "web-eip-bandwidth-" + eipID[:4]
	if pips[0].Status != "ACTIVE" || pips[0].PublicIPAddress != "192.0.2.1" ||
		pips[0].PortID != addrs[0].PortID || pips[0].PrivateIPAddress != addrs[0].Addr ||
		pips[0].BandwidthName != wantBW || pips[0].BandwidthSize != 5 || pips[0].BandwidthShareType != "PER" {
		t.Fatalf("publicip = %+v, want ACTIVE with bandwidth %q", pips[0], wantBW)
	}

	// Delete server with delete_publicip: false -> EIP survives unbound as DOWN.
	status, out = e.call(t, http.MethodPost, serversPath+"/delete", `{"servers": [{"id": "`+ids[0]+`"}], "delete_publicip": false}`)
	if status != http.StatusOK {
		t.Fatalf("delete server: %d %s", status, out)
	}
	e.settle(t)

	status, out = e.callVPC(t, http.MethodGet, "/v1/{project}/publicips", "")
	if status != http.StatusOK {
		t.Fatalf("list publicips after unbind: %d %s", status, out)
	}
	pips = decodeInto[pipListResp](t, out).PublicIPs
	if len(pips) != 1 || pips[0].ID != eipID || pips[0].Status != "DOWN" || pips[0].PortID != "" {
		t.Fatalf("publicip after delete_publicip=false: %+v, want DOWN unbound", pips)
	}

	// 2. Bind that existing EIP to a new server via publicip.id, then delete with delete_publicip: true.
	_, ids2 := e.mustCreate(t, n.serverBody("name", `"web-reuse"`, "publicip", `{"id": "`+eipID+`"}`))
	e.settle(t)
	status, out = e.call(t, http.MethodGet, serversPath+"/"+ids2[0], "")
	if status != http.StatusOK {
		t.Fatalf("show server 2: %d %s", status, out)
	}
	addrs2 := decodeInto[serverResponse](t, out).Server.Addresses[n.vpcID]
	if len(addrs2) != 2 || addrs2[1].Type != "floating" || addrs2[1].Addr != "192.0.2.1" {
		t.Fatalf("server 2 addresses = %+v", addrs2)
	}
	status, out = e.call(t, http.MethodPost, serversPath+"/delete", `{"servers": [{"id": "`+ids2[0]+`"}], "delete_publicip": true}`)
	if status != http.StatusOK {
		t.Fatalf("delete server 2: %d %s", status, out)
	}
	e.settle(t)
	status, _ = e.callVPC(t, http.MethodGet, "/v1/{project}/publicips/"+eipID, "")
	if status != http.StatusNotFound {
		t.Fatalf("GET deleted EIP status = %d, want 404", status)
	}

	// 3. Create server with delete_on_termination: true -> reclaims 192.0.2.1 and releases even when delete_publicip is false.
	_, ids3 := e.mustCreate(t, n.serverBody(
		"name", `"web-dot"`,
		"publicip", `{"eip": {"iptype": "5_bgp", "bandwidth": {"size": 5, "sharetype": "PER"}}, "delete_on_termination": true}`,
	))
	e.settle(t)
	status, out = e.call(t, http.MethodGet, serversPath+"/"+ids3[0], "")
	if status != http.StatusOK {
		t.Fatalf("show server 3: %d %s", status, out)
	}
	addrs3 := decodeInto[serverResponse](t, out).Server.Addresses[n.vpcID]
	if len(addrs3) != 2 || addrs3[1].Addr != "192.0.2.1" {
		t.Fatalf("server 3 addresses = %+v, want reclaimed 192.0.2.1", addrs3)
	}
	status, out = e.call(t, http.MethodPost, serversPath+"/delete", `{"servers": [{"id": "`+ids3[0]+`"}], "delete_publicip": false}`)
	if status != http.StatusOK {
		t.Fatalf("delete server 3: %d %s", status, out)
	}
	e.settle(t)
	status, out = e.callVPC(t, http.MethodGet, "/v1/{project}/publicips", "")
	if status != http.StatusOK || len(decodeInto[pipListResp](t, out).PublicIPs) != 0 {
		t.Fatalf("EIP with delete_on_termination survived delete: %d %s", status, out)
	}

	// 4. WHOLE shared bandwidth with ECS create and delete.
	status, out = e.callVPC(t, http.MethodPost, "/v2.0/{project}/bandwidths", `{"bandwidth": {"name": "shared-ecs-bw", "size": 20}}`)
	if status != http.StatusOK {
		t.Fatalf("create shared bandwidth: %d %s", status, out)
	}
	type bwRespShape struct {
		Bandwidth struct {
			ID           string `json:"id"`
			PublicIPInfo []any  `json:"publicip_info"`
		} `json:"bandwidth"`
	}
	bwResp := decodeInto[bwRespShape](t, out)
	sharedBWID := bwResp.Bandwidth.ID

	_, ids4 := e.mustCreate(t, n.serverBody(
		"name", `"web-whole"`,
		"publicip", `{"eip": {"iptype": "5_bgp", "bandwidth": {"sharetype": "WHOLE", "id": "`+sharedBWID+`"}}}`,
	))
	e.settle(t)
	status, out = e.call(t, http.MethodPost, serversPath+"/delete", `{"servers": [{"id": "`+ids4[0]+`"}], "delete_publicip": true}`)
	if status != http.StatusOK {
		t.Fatalf("delete server 4: %d %s", status, out)
	}
	e.settle(t)
	status, out = e.callVPC(t, http.MethodGet, "/v1/{project}/bandwidths/"+sharedBWID, "")
	if status != http.StatusOK {
		t.Fatalf("shared bandwidth missing after server delete: %d %s", status, out)
	}
	bwResp = decodeInto[bwRespShape](t, out)
	if len(bwResp.Bandwidth.PublicIPInfo) != 0 {
		t.Fatalf("shared bandwidth publicip_info = %+v, want empty", bwResp.Bandwidth.PublicIPInfo)
	}

	// 5. EIPs bound after server creation (including on a second NIC) show up as floating addresses.
	sn2, err := e.network.CreateSubnet(t.Context(), testTenant.vpc(), vpc.CreateSubnetOption{
		Name: "subnet-2", CIDR: "192.168.2.0/24", GatewayIP: "192.168.2.1", VPCID: n.vpcID,
	})
	if err != nil {
		t.Fatalf("CreateSubnet(2): %v", err)
	}
	e.settle(t)
	_, ids5 := e.mustCreate(t, n.serverBody(
		"name", `"web-late-bind"`,
		"nics", `[{"subnet_id": "`+n.subnetID+`"}, {"subnet_id": "`+sn2.ID+`"}]`,
	))
	e.settle(t)
	srv5 := e.server(t, ids5[0])

	// Create two unbound EIPs, settle, then bind one to each NIC.
	var lateIDs [2]string
	for i := range 2 {
		status, out = e.callVPC(t, http.MethodPost, "/v1/{project}/publicips",
			fmt.Sprintf(`{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "late-%d", "size": 5, "share_type": "PER"}}`, i))
		if status != http.StatusOK {
			t.Fatalf("create late EIP %d: %d %s", i, status, out)
		}
		created := decodeInto[struct {
			PublicIP struct {
				ID string `json:"id"`
			} `json:"publicip"`
		}](t, out)
		lateIDs[i] = created.PublicIP.ID
	}
	e.settle(t)
	for i := range 2 {
		status, out = e.callVPC(t, http.MethodPut, "/v1/{project}/publicips/"+lateIDs[i],
			`{"publicip": {"port_id": "`+srv5.NICs[i].PortID+`"}}`)
		if status != http.StatusOK {
			t.Fatalf("bind late EIP %d: %d %s", i, status, out)
		}
	}

	status, out = e.call(t, http.MethodGet, serversPath+"/"+ids5[0], "")
	if status != http.StatusOK {
		t.Fatalf("show server 5: %d %s", status, out)
	}
	addrs5 := decodeInto[serverResponse](t, out).Server.Addresses[n.vpcID]
	if len(addrs5) != 4 ||
		addrs5[0].Type != "fixed" || addrs5[1].Type != "fixed" ||
		addrs5[2].Type != "floating" || addrs5[2].PortID != srv5.NICs[0].PortID || addrs5[2].Addr != "192.0.2.1" ||
		addrs5[3].Type != "floating" || addrs5[3].PortID != srv5.NICs[1].PortID || addrs5[3].Addr != "192.0.2.2" {
		t.Fatalf("server 5 addresses after late bind = %+v", addrs5)
	}

	// Unbind the second EIP -> only the first floating address remains.
	status, out = e.callVPC(t, http.MethodPut, "/v1/{project}/publicips/"+lateIDs[1], `{"publicip": {}}`)
	if status != http.StatusOK {
		t.Fatalf("unbind late EIP: %d %s", status, out)
	}
	status, out = e.call(t, http.MethodGet, serversPath+"/"+ids5[0], "")
	if status != http.StatusOK {
		t.Fatalf("show server 5 after unbind: %d %s", status, out)
	}
	addrs5 = decodeInto[serverResponse](t, out).Server.Addresses[n.vpcID]
	if len(addrs5) != 3 || addrs5[2].Addr != "192.0.2.1" {
		t.Fatalf("server 5 addresses after unbind = %+v", addrs5)
	}
}

func TestCreateServerPublicIPErrorRollsBack(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	n := e.mustNetwork(t, testTenant, "192.168.1.0/24")

	// Create one existing DOWN EIP for rollback tests.
	status, out := e.callVPC(t, http.MethodPost, "/v1/{project}/publicips",
		`{"publicip": {"type": "5_bgp"}, "bandwidth": {"name": "existing-bw", "size": 5, "share_type": "PER"}}`)
	if status != http.StatusOK {
		t.Fatalf("create existing EIP: %d %s", status, out)
	}
	existingID := decodeInto[struct {
		PublicIP struct {
			ID string `json:"id"`
		} `json:"publicip"`
	}](t, out).PublicIP.ID
	e.settle(t)

	badCases := []struct {
		name     string
		publicip string
		count    string
	}{
		{"invalid iptype", `{"eip": {"iptype": "bad_type", "bandwidth": {"size": 5, "sharetype": "PER"}}}`, `1`},
		{"unknown existing id", `{"id": "` + unknownID + `"}`, `1`},
		{"both id and eip", `{"id": "` + existingID + `", "eip": {"iptype": "5_bgp", "bandwidth": {"size": 5, "sharetype": "PER"}}}`, `1`},
		{"empty publicip object", `{}`, `1`},
		{"count 2 with existing id", `{"id": "` + existingID + `"}`, `2`},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			status, out := e.call(t, http.MethodPost, serversPath, n.serverBody("count", tc.count, "publicip", tc.publicip))
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d %s, want 400", status, out)
			}
			errResp := decodeInto[struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}](t, out)
			if errResp.Error.Code != "Ecs.0005" || errResp.Error.Message == "" {
				t.Fatalf("error = %+v, want Ecs.0005 with message", errResp.Error)
			}
		})
	}

	// No servers were left behind and no private IPs were leaked.
	if all, _ := e.svc.ListServers(t.Context(), testTenant, ListServersFilter{}); len(all) != 0 {
		t.Fatalf("%d servers left after failed creates", len(all))
	}
	if free := e.subnetFree(t, n.subnetID); free != 251 {
		t.Fatalf("subnet has %d free addresses, want 251", free)
	}
	// The existing EIP used in the failed count=2 create must still exist and be DOWN (unbound).
	status, out = e.callVPC(t, http.MethodGet, "/v1/{project}/publicips/"+existingID, "")
	if status != http.StatusOK {
		t.Fatalf("existing EIP lost on rollback: %d %s", status, out)
	}
	gotExisting := decodeInto[struct {
		PublicIP struct {
			Status string `json:"status"`
			PortID string `json:"port_id"`
		} `json:"publicip"`
	}](t, out).PublicIP
	if gotExisting.Status != "DOWN" || gotExisting.PortID != "" {
		t.Fatalf("existing EIP after count=2 rollback = %+v, want DOWN unbound", gotExisting)
	}

	// Multi-server create hitting EIP quota rolls back the newly created EIP of server 0 as well.
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; _ = st.Close() })

	gen := ids.NewSeeded(99)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	eipSvc, err := eip.New(eip.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Ports: vpcSvc, MaxPerProject: 1, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	imsSvc, err := ims.New(ims.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now, DefaultProjectID: testProject})
	if err != nil {
		t.Fatal(err)
	}
	evsSvc, err := evs.New(evs.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Images: imsSvc, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	ecsSvc, err := New(Deps{
		Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now,
		Network: vpcSvc, EIPs: eipSvc, Images: imsSvc, Volumes: evsSvc,
	})
	if err != nil {
		t.Fatal(err)
	}
	evsSvc.SetServers(ecsSvc)
	vpcSvc.SetPorts(ecsSvc)

	v, err := vpcSvc.CreateVPC(t.Context(), testTenant.vpc(), vpc.CreateVPCOption{CIDR: ptr("10.0.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := vpcSvc.CreateSubnet(t.Context(), testTenant.vpc(), vpc.CreateSubnetOption{
		Name: "qsn", CIDR: "10.0.1.0/24", GatewayIP: "10.0.1.1", VPCID: v.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(testDelay)
	_ = engine.WaitIdle(t.Context())

	_, _, err = ecsSvc.CreateServers(t.Context(), testTenant, CreateServerOption{
		Name:       "quota-pair",
		ImageRef:   ubuntuImage,
		FlavorRef:  "s6.large.2",
		VPCID:      v.ID,
		NICs:       []CreateNIC{{SubnetID: sn.ID}},
		RootVolume: &CreateVolume{VolumeType: "GPSSD"},
		Count:      ptr(2),
		PublicIP: &CreatePublicIP{
			EIP: &CreateServerEIP{
				IPType:    "5_bgp",
				Bandwidth: &CreateServerBandwidth{Size: 5, ShareType: "PER"},
			},
		},
	})
	if codeOf(err) != "Ecs.0005" {
		t.Fatalf("quota rollback err = %v, want Ecs.0005", err)
	}
	if all, _ := ecsSvc.ListServers(t.Context(), testTenant, ListServersFilter{}); len(all) != 0 {
		t.Fatalf("%d servers left after EIP quota failure", len(all))
	}
	if addrsByPort, err := eipSvc.AddressesByPort(t.Context(), testTenant.vpc()); err != nil || len(addrsByPort) != 0 {
		t.Fatalf("EIPs left bound after quota rollback: %v, %v", addrsByPort, err)
	}
	if gotSN, err := vpcSvc.GetSubnet(t.Context(), testTenant.vpc(), sn.ID); err != nil || gotSN.AvailableIPAddressCount != 251 {
		t.Fatalf("subnet after quota rollback: %+v, %v", gotSN, err)
	}
}

func TestCreateServerWithoutEIPServiceIgnoresPublicIP(t *testing.T) {
	t.Parallel()
	st := store.NewMemory()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(testEpoch)
	engine := lifecycle.New(lifecycle.Options{Delay: testDelay, Clock: clock, Logger: log})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); engine.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done; _ = st.Close() })

	gen := ids.NewSeeded(21)
	vpcSvc, err := vpc.New(vpc.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	imsSvc, err := ims.New(ims.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now, DefaultProjectID: testProject})
	if err != nil {
		t.Fatal(err)
	}
	evsSvc, err := evs.New(evs.Deps{Store: st, Engine: engine, IDs: gen, Logger: log, Images: imsSvc, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	ecsSvc, err := New(Deps{
		Store: st, Engine: engine, IDs: gen, Logger: log, Now: clock.Now,
		Network: vpcSvc, Images: imsSvc, Volumes: evsSvc, // EIPs intentionally nil
	})
	if err != nil {
		t.Fatal(err)
	}
	evsSvc.SetServers(ecsSvc)
	v, err := vpcSvc.CreateVPC(t.Context(), testTenant.vpc(), vpc.CreateVPCOption{CIDR: ptr("10.1.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := vpcSvc.CreateSubnet(t.Context(), testTenant.vpc(), vpc.CreateSubnetOption{
		Name: "s1", CIDR: "10.1.1.0/24", GatewayIP: "10.1.1.1", VPCID: v.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(testDelay)
	_ = engine.WaitIdle(t.Context())

	_, ids, err := ecsSvc.CreateServers(t.Context(), testTenant, CreateServerOption{
		Name:       "no-eip",
		ImageRef:   ubuntuImage,
		FlavorRef:  "s6.large.2",
		VPCID:      v.ID,
		NICs:       []CreateNIC{{SubnetID: sn.ID}},
		RootVolume: &CreateVolume{VolumeType: "GPSSD"},
		PublicIP: &CreatePublicIP{
			EIP: &CreateServerEIP{
				IPType:    "5_bgp",
				Bandwidth: &CreateServerBandwidth{Size: 5, ShareType: "PER"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServers with nil EIPs: %v", err)
	}
	srv, err := ecsSvc.GetServer(t.Context(), testTenant, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	detail := ecsSvc.detail(t.Context(), testTenant, srv, nil)
	addrs := detail.Addresses[v.ID]
	if len(addrs) != 1 || addrs[0].Type != "fixed" {
		t.Fatalf("addresses with nil EIPs = %+v, want only fixed address (no invented floating IP)", addrs)
	}
}

func TestResumeDeleteHonoursDeletePublicIP(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := newEnvWith(t, st, "")
	n := first.mustNetwork(t, testTenant, "192.168.1.0/24")

	_, ids := first.mustCreate(t, n.serverBody(
		"name", `"resumed-del"`,
		"publicip", `{"eip": {"iptype": "5_bgp", "bandwidth": {"size": 5, "sharetype": "PER"}}, "delete_on_termination": false}`,
	))
	first.settle(t)

	status, out := first.call(t, http.MethodPost, serversPath+"/delete", `{"servers": [{"id": "`+ids[0]+`"}], "delete_publicip": true}`)
	if status != http.StatusOK {
		t.Fatalf("delete: %d %s", status, out)
	}
	first.engine.CancelAll()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened := newEnvWith(t, st, "")
	if err := reopened.svc.Resume(t.Context()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	reopened.settle(t)

	status, out = reopened.callVPC(t, http.MethodGet, "/v1/{project}/publicips", "")
	if status != http.StatusOK {
		t.Fatalf("list publicips: %d %s", status, out)
	}
	got := decodeInto[struct {
		PublicIPs []any `json:"publicips"`
	}](t, out)
	if len(got.PublicIPs) != 0 {
		t.Fatalf("EIP survived resumed delete with delete_publicip=true: %s", out)
	}
}
