package sdk

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	ecsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	rdsv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3/model"
	vpcv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	v3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
)

// cloud is one set of SDK clients for an emulator address. Clients are
// rebuilt after every restart so no connection outlives its server.
type cloud struct {
	net     *vpcv2.VpcClient
	compute *ecsv2.EcsClient
	db      *rdsv3.RdsClient
	store   *obs.ObsClient
}

func cloudAt(t *testing.T, addr string) cloud {
	t.Helper()
	return cloud{
		net:     newV2At(t, addr, realEndpoint),
		compute: newECSAt(t, addr),
		db:      newRDSAt(t, addr),
		store:   newOBSAt(t, addr, "AKpersistence", obs.SignatureObs, false),
	}
}

// TestPersistenceAcrossRestarts is end-to-end scenario 7 of the plan:
// with -persist, a stack survives a graceful restart in the middle of
// its asynchronous work, and acknowledged writes survive a crash.
func TestPersistenceAcrossRestarts(t *testing.T) {
	if emulatorBin == "" {
		t.Skip("needs an emulator binary of its own; WEISTACK_ADDR names a shared one")
	}
	t.Parallel()

	dataDir := t.TempDir()
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	start := func() *emulator {
		t.Helper()
		// A delay long enough that the creations below are certainly
		// still in flight when the emulator stops.
		e, err := launch(emulatorBin, port,
			"WEISTACK_PERSIST=1", "WEISTACK_DATA_DIR="+dataDir,
			"WEISTACK_TLS_DIR="+filepath.Join(dataDir, "tls"), "WEISTACK_LIFECYCLE_DELAY=2s")
		if err != nil {
			t.Fatalf("starting the emulator: %v", err)
		}
		return e
	}

	// --- First run: build a stack and stop it half way. ---------------
	e := start()
	c := cloudAt(t, e.addr)

	vc, err := c.net.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("persist-vpc"), Cidr: ptr("10.70.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	eventually(t, "the VPC to become OK", func() bool {
		s, err := c.net.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})
	sc, err := c.net.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "persist-subnet", Cidr: "10.70.1.0/24", GatewayIp: "10.70.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	eventually(t, "the subnet to become ACTIVE", func() bool {
		s, err := c.net.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})
	gc, err := newV3At(t, e.addr).CreateSecurityGroup(&v3.CreateSecurityGroupRequest{Body: &v3.CreateSecurityGroupRequestBody{
		SecurityGroup: &v3.CreateSecurityGroupOption{Name: "persist-sg"},
	}})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	groupID := gc.SecurityGroup.Id

	createServer := func(c cloud, name string) (jobID, serverID string) {
		t.Helper()
		res, err := c.compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
			Server: &ecs.PostPaidServer{
				Name: name, ImageRef: "455b5860-f96d-5d89-baaa-ec6adb758c5b", FlavorRef: "s6.large.2", Vpcid: vpcID,
				Nics:           []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
				RootVolume:     &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
				SecurityGroups: &[]ecs.PostPaidServerSecurityGroup{{Id: &groupID}},
			},
		}})
		if err != nil || res.JobId == nil || res.ServerIds == nil || len(*res.ServerIds) != 1 {
			t.Fatalf("CreatePostPaidServers(%s) = %+v, %v", name, res, err)
		}
		return *res.JobId, (*res.ServerIds)[0]
	}
	serverJob, serverID := createServer(c, "persist-server")

	created, err := c.db.CreateInstance(&rds.CreateInstanceRequest{Body: &rds.InstanceRequest{
		Name: "persist-mysql", Region: region, VpcId: vpcID, SubnetId: subnetID, SecurityGroupId: groupID,
		Password:         ptr("Weistack@2026"),
		Datastore:        &rds.Datastore{Type: rds.GetDatastoreTypeEnum().MY_SQL, Version: "8.0"},
		FlavorRef:        "rds.mysql.n1.large.2",
		Volume:           &rds.Volume{Type: rds.GetVolumeTypeEnum().CLOUDSSD, Size: 40},
		AvailabilityZone: region + "a",
	}})
	if err != nil || created.Instance == nil || created.Instance.Id == nil || created.JobId == nil {
		t.Fatalf("CreateInstance = %+v, %v", created, err)
	}
	dbID, dbJob := *created.Instance.Id, *created.JobId

	const bucket, kept = "persist-bucket", "Bytes on disk outlive the process."
	if _, err := c.store.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	putObject(t, c.store, bucket, "kept.txt", kept)
	initIn := &obs.InitiateMultipartUploadInput{}
	initIn.Bucket, initIn.Key = bucket, "assembled.bin"
	upload, err := c.store.InitiateMultipartUpload(initIn)
	if err != nil {
		t.Fatalf("InitiateMultipartUpload: %v", err)
	}
	firstPart := strings.Repeat("p", 100<<10)
	part1, err := c.store.UploadPart(&obs.UploadPartInput{
		Bucket: bucket, Key: "assembled.bin", UploadId: upload.UploadId, PartNumber: 1, Body: strings.NewReader(firstPart),
	})
	if err != nil {
		t.Fatalf("UploadPart(1): %v", err)
	}

	// Both creations are still running when the emulator goes down.
	if s, err := c.compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID}); err != nil || s.Server.Status != "BUILD" {
		t.Fatalf("server before the restart: %+v, %v (want BUILD)", s, err)
	}
	if l, err := c.db.ListInstances(&rds.ListInstancesRequest{Id: &dbID}); err != nil || len(*l.Instances) != 1 || (*l.Instances)[0].Status != "BUILD" {
		t.Fatalf("instance before the restart: %+v, %v (want BUILD)", l, err)
	}
	if err := e.stop(); err != nil {
		t.Fatalf("graceful stop: %v", err)
	}

	// --- Second run: the work finishes and nothing is lost. -----------
	e = start()
	c = cloudAt(t, e.addr)

	eventually(t, "the interrupted server creation to finish", func() bool {
		job, err := c.compute.ShowJob(&ecs.ShowJobRequest{JobId: serverJob})
		return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
	})
	first, err := c.compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil || first.Server.Status != "ACTIVE" {
		t.Fatalf("server after the restart: %+v, %v", first, err)
	}
	waitRDSJob(t, c.db, "the interrupted instance creation", dbJob)
	if l, err := c.db.ListInstances(&rds.ListInstancesRequest{Id: &dbID}); err != nil || (*l.Instances)[0].Status != "ACTIVE" {
		t.Fatalf("instance after the restart: %+v, %v", l, err)
	}
	if v, err := c.net.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID}); err != nil || v.Vpc.Name != "persist-vpc" {
		t.Fatalf("VPC after the restart: %+v, %v", v, err)
	}
	if got := getObject(t, c.store, bucket, "kept.txt"); got != kept {
		t.Fatalf("object after the restart: %q", got)
	}

	// The upload carries on where it stopped.
	lastPart := "and the rest, after a restart"
	part2, err := c.store.UploadPart(&obs.UploadPartInput{
		Bucket: bucket, Key: "assembled.bin", UploadId: upload.UploadId, PartNumber: 2, Body: strings.NewReader(lastPart),
	})
	if err != nil {
		t.Fatalf("UploadPart(2) after the restart: %v", err)
	}
	if _, err := c.store.CompleteMultipartUpload(&obs.CompleteMultipartUploadInput{
		Bucket: bucket, Key: "assembled.bin", UploadId: upload.UploadId,
		Parts: []obs.Part{{PartNumber: 1, ETag: part1.ETag}, {PartNumber: 2, ETag: part2.ETag}},
	}); err != nil {
		t.Fatalf("CompleteMultipartUpload after the restart: %v", err)
	}
	if got := getObject(t, c.store, bucket, "assembled.bin"); got != firstPart+lastPart {
		t.Fatalf("assembled object: %d bytes, want %d", len(got), len(firstPart)+len(lastPart))
	}

	// Allocations survived too: a new server gets another address and
	// another ID.
	secondJob, secondID := createServer(c, "persist-server-2")
	eventually(t, "the second server", func() bool {
		job, err := c.compute.ShowJob(&ecs.ShowJobRequest{JobId: secondJob})
		return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
	})
	second, err := c.compute.ShowServer(&ecs.ShowServerRequest{ServerId: secondID})
	if err != nil {
		t.Fatal(err)
	}
	ip := func(s *ecs.ShowServerResponse) string {
		for _, addrs := range s.Server.Addresses {
			for _, a := range addrs {
				return a.Addr
			}
		}
		return ""
	}
	if secondID == serverID || ip(second) == "" || ip(second) == ip(first) {
		t.Fatalf("second server %s at %q, first %s at %q", secondID, ip(second), serverID, ip(first))
	}

	// --- Crash: acknowledged writes survive a kill. -------------------
	crashed, err := c.net.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("before-the-crash"), Cidr: ptr("10.71.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	putObject(t, c.store, bucket, "crash.txt", "written just before the kill")
	e.kill()

	e = start()
	c = cloudAt(t, e.addr)
	eventually(t, "the VPC created before the crash to become OK", func() bool {
		v, err := c.net.ShowVpc(&v2.ShowVpcRequest{VpcId: crashed.Vpc.Id})
		return err == nil && v.Vpc.Status.Value() == "OK"
	})
	if got := getObject(t, c.store, bucket, "crash.txt"); got != "written just before the kill" {
		t.Fatalf("object after the crash: %q", got)
	}
	if err := e.stop(); err != nil {
		t.Fatalf("final stop: %v", err)
	}
}

func putObject(t *testing.T, c *obs.ObsClient, bucket, key, body string) {
	t.Helper()
	in := &obs.PutObjectInput{Body: strings.NewReader(body)}
	in.Bucket, in.Key = bucket, key
	if _, err := c.PutObject(in); err != nil {
		t.Fatalf("PutObject(%s): %v", key, err)
	}
}

func getObject(t *testing.T, c *obs.ObsClient, bucket, key string) string {
	t.Helper()
	in := &obs.GetObjectInput{}
	in.Bucket, in.Key = bucket, key
	out, err := c.GetObject(in)
	if err != nil {
		t.Fatalf("GetObject(%s): %v", key, err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", key, err)
	}
	return string(body)
}
