package sdk

import (
	"strings"
	"testing"

	ecsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	v3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
)

func newECS(t *testing.T) *ecsv2.EcsClient {
	t.Helper()
	return newECSAt(t, emulatorAddr)
}

func newECSAt(t *testing.T, addr string) *ecsv2.EcsClient {
	t.Helper()
	hc, err := ecsv2.EcsClientBuilder().
		WithEndpoints([]string{"http://ecs." + region + ".myhuaweicloud.com"}).
		WithCredential(credentials(t)).
		WithHttpConfig(httpConfigAt(addr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building ECS client: %v", err)
	}
	return ecsv2.NewEcsClient(hc)
}

// TestFlavorsAndZones is what a script does before creating a server:
// pick an availability zone, then a flavor sold there.
func TestFlavorsAndZones(t *testing.T) {
	c := newECS(t)

	zones, err := c.NovaListAvailabilityZones(&ecs.NovaListAvailabilityZonesRequest{})
	if err != nil {
		t.Fatalf("NovaListAvailabilityZones: %v", err)
	}
	if zones.AvailabilityZoneInfo == nil || len(*zones.AvailabilityZoneInfo) != 3 {
		t.Fatalf("zones = %+v, want 3", zones.AvailabilityZoneInfo)
	}
	az := (*zones.AvailabilityZoneInfo)[0]
	if az.ZoneName != region+"a" || az.ZoneState == nil || !az.ZoneState.Available {
		t.Errorf("first zone = %+v", az)
	}

	listed, err := c.ListFlavors(&ecs.ListFlavorsRequest{AvailabilityZone: &az.ZoneName})
	if err != nil {
		t.Fatalf("ListFlavors: %v", err)
	}
	if listed.Flavors == nil || len(*listed.Flavors) < 20 {
		t.Fatalf("ListFlavors returned %d flavors, want at least the 20 built-in ones", len(*listed.Flavors))
	}
	var found *ecs.Flavor
	for i, f := range *listed.Flavors {
		if f.Id == "s6.large.2" {
			found = &(*listed.Flavors)[i]
		}
	}
	if found == nil {
		t.Fatal("s6.large.2 is not in the flavor list")
	}
	if found.Vcpus != "2" || found.Ram != 4096 || found.Name != "s6.large.2" || !found.OsFlavorAccessisPublic || len(found.Links) != 2 {
		t.Errorf("s6.large.2 = %+v", found)
	}
	spec := found.OsExtraSpecs
	if spec == nil || spec.Ecsgeneration == nil || *spec.Ecsgeneration != "s6" ||
		spec.Ecsperformancetype == nil || *spec.Ecsperformancetype != "normal" ||
		spec.Condoperationstatus == nil || *spec.Condoperationstatus != "normal" {
		t.Errorf("s6.large.2 extra specs = %+v", spec)
	}

	one, err := c.ListFlavors(&ecs.ListFlavorsRequest{FlavorId: ptr("m7.large.8")})
	if err != nil || one.Flavors == nil || len(*one.Flavors) != 1 || (*one.Flavors)[0].Ram != 16384 {
		t.Fatalf("ListFlavors(flavor_id) = %+v, %v", one, err)
	}

	_, err = c.ListFlavors(&ecs.ListFlavorsRequest{Marker: ptr("no.such.flavor")})
	wantError(t, err, 400, "Ecs.0005")
}

// TestServerEndToEnd is end-to-end scenarios 1 and 2 of the plan, driven
// entirely by the official SDK across three services:
//
//	VPC -> subnet -> security group -> server from a public image ->
//	wait for ACTIVE -> private image of the server -> second server from
//	that image -> delete everything in reverse order.
func TestServerEndToEnd(t *testing.T) {
	net2 := newV2(t, realEndpoint)
	net3 := newV3(t)
	compute := newECS(t)
	images := newIMS(t)

	// --- Network ------------------------------------------------------
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("e2e-vpc"), Cidr: ptr("172.16.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	eventually(t, "the VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})
	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "e2e-subnet", Cidr: "172.16.10.0/24", GatewayIp: "172.16.10.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	eventually(t, "the subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})
	gc, err := net3.CreateSecurityGroup(&v3.CreateSecurityGroupRequest{Body: &v3.CreateSecurityGroupRequestBody{
		SecurityGroup: &v3.CreateSecurityGroupOption{Name: "e2e-sg"},
	}})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	groupID := gc.SecurityGroup.Id

	// --- Image and flavor ---------------------------------------------
	listed, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || listed.Images == nil || len(*listed.Images) != 1 {
		t.Fatalf("finding the Ubuntu image: %+v, %v", listed, err)
	}
	publicImage := (*listed.Images)[0].Id

	// --- First server ---------------------------------------------------
	create := func(name, imageID string) (jobID, serverID string) {
		t.Helper()
		res, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
			Server: &ecs.PostPaidServer{
				Name:           name,
				ImageRef:       imageID,
				FlavorRef:      "s6.large.2",
				Vpcid:          vpcID,
				Nics:           []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
				RootVolume:     &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().GPSSD},
				SecurityGroups: &[]ecs.PostPaidServerSecurityGroup{{Id: &groupID}},
				ServerTags:     &[]ecs.PostPaidServerTag{{Key: "suite", Value: "sdk"}},
			},
		}})
		if err != nil {
			t.Fatalf("CreatePostPaidServers(%s): %v", name, err)
		}
		if res.JobId == nil || res.ServerIds == nil || len(*res.ServerIds) != 1 {
			t.Fatalf("CreatePostPaidServers(%s) = %+v", name, res)
		}
		return *res.JobId, (*res.ServerIds)[0]
	}
	waitJob := func(jobID string) *ecs.ShowJobResponse {
		t.Helper()
		var last *ecs.ShowJobResponse
		eventually(t, "job "+jobID+" to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: jobID})
			if err != nil {
				t.Fatalf("ShowJob: %v", err)
			}
			last = job
			return job.Status != nil && job.Status.Value() != "RUNNING" && job.Status.Value() != "INIT"
		})
		if last.Status.Value() != "SUCCESS" {
			t.Fatalf("job %s ended %s: %v", jobID, last.Status.Value(), last.FailReason)
		}
		return last
	}

	jobID, serverID := create("e2e-server", publicImage)

	building, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil {
		t.Fatalf("ShowServer: %v", err)
	}
	if building.Server.Status != "BUILD" {
		t.Errorf("new server status = %q, want BUILD", building.Server.Status)
	}

	job := waitJob(jobID)
	if job.JobType == nil || *job.JobType != "createServer" || job.Entities == nil || job.Entities.SubJobs == nil ||
		len(*job.Entities.SubJobs) != 1 || (*job.Entities.SubJobs)[0].Entities == nil ||
		*(*job.Entities.SubJobs)[0].Entities.ServerId != serverID {
		t.Errorf("create job = %+v", job)
	}

	shown, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	if err != nil {
		t.Fatalf("ShowServer: %v", err)
	}
	srv := shown.Server
	addrs := srv.Addresses[vpcID]
	if srv.Status != "ACTIVE" || srv.Name != "e2e-server" || srv.Flavor == nil || srv.Flavor.Id != "s6.large.2" ||
		srv.Flavor.Vcpus != "2" || srv.Image == nil || srv.Image.Id != publicImage || srv.OSEXTSTSpowerState != 1 ||
		srv.OSEXTSTSvmState != "active" || srv.TenantId != projectID {
		t.Errorf("active server = %+v", srv)
	}
	if len(addrs) != 1 || addrs[0].Addr != "172.16.10.2" || addrs[0].Version != "4" {
		t.Errorf("addresses = %+v, want the subnet's first free address 172.16.10.2", addrs)
	}
	if len(srv.SecurityGroups) != 1 || srv.SecurityGroups[0].Id != groupID || srv.SecurityGroups[0].Name != "e2e-sg" {
		t.Errorf("security groups = %+v", srv.SecurityGroups)
	}
	if srv.Tags == nil || len(*srv.Tags) != 1 || (*srv.Tags)[0] != "suite=sdk" {
		t.Errorf("tags = %v", srv.Tags)
	}
	if srv.Metadata["image_name"] != "Ubuntu 22.04 server 64bit" || srv.Metadata["vpc_id"] != vpcID {
		t.Errorf("metadata = %v", srv.Metadata)
	}

	list, err := compute.ListServersDetails(&ecs.ListServersDetailsRequest{Name: ptr("e2e-"), Status: ptr("ACTIVE")})
	if err != nil || list.Count == nil || *list.Count != 1 || list.Servers == nil || (*list.Servers)[0].Id != serverID {
		t.Fatalf("ListServersDetails = %+v, %v", list, err)
	}

	// --- Dependency errors (scenario 5) --------------------------------
	_, err = net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
	wantError(t, err, 500, "VPC.0208") // an address of the subnet is in use
	_, err = compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name: "wrong-subnet", ImageRef: publicImage, FlavorRef: "s6.large.2", Vpcid: vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: ptr(unknownID)}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
		},
	}})
	wantError(t, err, 400, "Ecs.0038")
	_, err = compute.ShowServer(&ecs.ShowServerRequest{ServerId: unknownID})
	wantError(t, err, 404, "Ecs.0114")
	_, err = compute.ShowJob(&ecs.ShowJobRequest{JobId: "00000000000000000000000000000000"})
	wantError(t, err, 400, "Common.0011")

	// --- Private image of the server (scenario 2) -----------------------
	ic, err := images.CreateImage(&ims.CreateImageRequest{Body: &ims.CreateImageRequestBody{
		Name: ptr("e2e-image"), InstanceId: &serverID, Description: ptr("made by the SDK suite"),
	}})
	if err != nil || ic.JobId == nil {
		t.Fatalf("CreateImage: %+v, %v", ic, err)
	}
	var imageID string
	eventually(t, "the image job to succeed", func() bool {
		ij, err := images.ShowJob(&ims.ShowJobRequest{JobId: *ic.JobId})
		if err != nil {
			t.Fatalf("IMS ShowJob: %v", err)
		}
		if ij.Entities != nil && ij.Entities.ImageId != nil {
			imageID = *ij.Entities.ImageId
		}
		return ij.Status != nil && ij.Status.Value() == "SUCCESS"
	})
	img, err := images.GlanceShowImage(&ims.GlanceShowImageRequest{ImageId: imageID})
	if err != nil || img.Status == nil || img.Status.Value() != "active" || img.Name == nil || *img.Name != "e2e-image" ||
		img.Visibility == nil || img.Visibility.Value() != "private" || img.OsVersion == nil || *img.OsVersion != "Ubuntu 22.04 server 64bit" {
		t.Fatalf("private image = %+v, %v", img, err)
	}

	replace := ims.GetUpdateImageRequestBodyOpEnum().REPLACE
	renamed, err := images.UpdateImage(&ims.UpdateImageRequest{ImageId: imageID, Body: &[]ims.UpdateImageRequestBody{
		{Op: replace, Path: "/name", Value: "e2e-image-renamed"},
	}})
	if err != nil || renamed.Name == nil || *renamed.Name != "e2e-image-renamed" {
		t.Fatalf("UpdateImage = %+v, %v", renamed, err)
	}

	// --- Second server, from the private image --------------------------
	jobID, cloneID := create("e2e-clone", imageID)
	waitJob(jobID)
	clone, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: cloneID})
	if err != nil || clone.Server.Status != "ACTIVE" || clone.Server.Image.Id != imageID ||
		clone.Server.Addresses[vpcID][0].Addr != "172.16.10.3" {
		t.Fatalf("clone = %+v, %v", clone, err)
	}

	// --- Teardown in reverse order ---------------------------------------
	del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
		Servers: []ecs.ServerId{{Id: serverID}, {Id: cloneID}},
	}})
	if err != nil || del.JobId == nil {
		t.Fatalf("DeleteServers: %+v, %v", del, err)
	}
	dj := waitJob(*del.JobId)
	if dj.Entities == nil || dj.Entities.SubJobsTotal == nil || *dj.Entities.SubJobsTotal != 2 {
		t.Errorf("delete job = %+v", dj)
	}
	_, err = compute.ShowServer(&ecs.ShowServerRequest{ServerId: serverID})
	wantError(t, err, 404, "Ecs.0114")

	if _, err := images.GlanceDeleteImage(&ims.GlanceDeleteImageRequest{ImageId: imageID}); err != nil {
		t.Fatalf("GlanceDeleteImage: %v", err)
	}
	if _, err := net3.DeleteSecurityGroup(&v3.DeleteSecurityGroupRequest{SecurityGroupId: groupID}); err != nil {
		t.Fatalf("DeleteSecurityGroup: %v", err)
	}
	if _, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID}); err != nil {
		t.Fatalf("DeleteSubnet after the servers are gone: %v", err)
	}
	if _, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID}); err != nil {
		t.Fatalf("DeleteVpc: %v", err)
	}
}

// TestServerOperations finishes end-to-end scenario 1: a running server
// is stopped, started, rebooted, resized, renamed and tagged, with every
// step waited for through its job as a real client would.
func TestServerOperations(t *testing.T) {
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)

	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("ops-vpc"), Cidr: ptr("10.20.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	eventually(t, "the VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})
	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "ops-subnet", Cidr: "10.20.1.0/24", GatewayIp: "10.20.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	eventually(t, "the subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})
	listed, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("CentOS 7.9 64bit")})
	if err != nil || listed.Images == nil || len(*listed.Images) != 1 {
		t.Fatalf("finding the CentOS image: %+v, %v", listed, err)
	}

	waitJob := func(what string, jobID *string, err error) {
		t.Helper()
		if err != nil || jobID == nil {
			t.Fatalf("%s: job %v, error %v", what, jobID, err)
		}
		eventually(t, what+" to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *jobID})
			if err != nil {
				t.Fatalf("ShowJob: %v", err)
			}
			if job.Status.Value() == "FAIL" {
				t.Fatalf("%s failed: %v", what, job.FailReason)
			}
			return job.Status.Value() == "SUCCESS"
		})
	}
	status := func(id string) string {
		t.Helper()
		s, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: id})
		if err != nil {
			t.Fatalf("ShowServer: %v", err)
		}
		return s.Server.Status
	}

	created, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name: "ops-server", ImageRef: (*listed.Images)[0].Id, FlavorRef: "s6.large.2", Vpcid: vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
		},
	}})
	if err != nil {
		t.Fatalf("CreatePostPaidServers: %v", err)
	}
	waitJob("create", created.JobId, nil)
	id := (*created.ServerIds)[0]
	servers := []ecs.ServerId{{Id: id}}

	// --- Stop, start, reboot -------------------------------------------
	soft := ecs.GetBatchStopServersOptionTypeEnum().SOFT
	stop, err := compute.BatchStopServers(&ecs.BatchStopServersRequest{Body: &ecs.BatchStopServersRequestBody{
		OsStop: &ecs.BatchStopServersOption{Servers: servers, Type: &soft},
	}})
	waitJob("stop", stop.JobId, err)
	if got := status(id); got != "SHUTOFF" {
		t.Fatalf("status after stop = %q", got)
	}

	// Stopping a stopped server is the plan's invalid-transition case.
	_, err = compute.BatchStopServers(&ecs.BatchStopServersRequest{Body: &ecs.BatchStopServersRequestBody{
		OsStop: &ecs.BatchStopServersOption{Servers: servers},
	}})
	wantError(t, err, 400, "Ecs.0100")

	start, err := compute.BatchStartServers(&ecs.BatchStartServersRequest{Body: &ecs.BatchStartServersRequestBody{
		OsStart: &ecs.BatchStartServersOption{Servers: servers},
	}})
	waitJob("start", start.JobId, err)
	if got := status(id); got != "ACTIVE" {
		t.Fatalf("status after start = %q", got)
	}
	_, err = compute.BatchStartServers(&ecs.BatchStartServersRequest{Body: &ecs.BatchStartServersRequestBody{
		OsStart: &ecs.BatchStartServersOption{Servers: servers},
	}})
	wantError(t, err, 400, "Ecs.0100")

	reboot, err := compute.BatchRebootServers(&ecs.BatchRebootServersRequest{Body: &ecs.BatchRebootServersRequestBody{
		Reboot: &ecs.BatchRebootSeversOption{Servers: servers, Type: ecs.GetBatchRebootSeversOptionTypeEnum().HARD},
	}})
	if err == nil && status(id) != "HARD_REBOOT" {
		t.Errorf("status during a hard reboot = %q", status(id))
	}
	waitJob("reboot", reboot.JobId, err)
	if got := status(id); got != "ACTIVE" {
		t.Fatalf("status after reboot = %q", got)
	}

	// --- Resize ----------------------------------------------------------
	_, err = compute.ResizePostPaidServer(&ecs.ResizePostPaidServerRequest{ServerId: id, Body: &ecs.ResizePostPaidServerRequestBody{
		Resize: &ecs.ResizePostPaidServerOption{FlavorRef: "s6.xlarge.2"},
	}})
	wantError(t, err, 400, "Ecs.0100") // running, and no stop mode
	_, err = compute.ResizePostPaidServer(&ecs.ResizePostPaidServerRequest{ServerId: id, Body: &ecs.ResizePostPaidServerRequestBody{
		Resize: &ecs.ResizePostPaidServerOption{FlavorRef: "s6.large.2", Mode: ptr("withStopServer")},
	}})
	wantError(t, err, 400, "Ecs.0810")

	resize, err := compute.ResizePostPaidServer(&ecs.ResizePostPaidServerRequest{ServerId: id, Body: &ecs.ResizePostPaidServerRequestBody{
		Resize: &ecs.ResizePostPaidServerOption{FlavorRef: "s6.xlarge.2", Mode: ptr("withStopServer")},
	}})
	waitJob("resize", resize.JobId, err)
	shown, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: id})
	if err != nil || shown.Server.Status != "ACTIVE" || shown.Server.Flavor.Id != "s6.xlarge.2" || shown.Server.Flavor.Vcpus != "4" {
		t.Fatalf("after resize: %+v, %v", shown, err)
	}

	// --- Rename ----------------------------------------------------------
	updated, err := compute.UpdateServer(&ecs.UpdateServerRequest{ServerId: id, Body: &ecs.UpdateServerRequestBody{
		Server: &ecs.UpdateServerOption{Name: ptr("ops-server-renamed"), Description: ptr("renamed by the SDK suite")},
	}})
	if err != nil || updated.Server == nil || updated.Server.Name != "ops-server-renamed" || updated.Server.Id != id ||
		updated.Server.Flavor == nil || updated.Server.Flavor.Id != "s6.xlarge.2" || len(updated.Server.Addresses[vpcID]) != 1 {
		t.Fatalf("UpdateServer = %+v, %v", updated, err)
	}
	_, err = compute.UpdateServer(&ecs.UpdateServerRequest{ServerId: id, Body: &ecs.UpdateServerRequestBody{
		Server: &ecs.UpdateServerOption{Name: ptr("not a valid name")},
	}})
	wantError(t, err, 400, "Ecs.0915")

	// --- Tags ------------------------------------------------------------
	if _, err := compute.BatchCreateServerTags(&ecs.BatchCreateServerTagsRequest{ServerId: id, Body: &ecs.BatchCreateServerTagsRequestBody{
		Action: ecs.GetBatchCreateServerTagsRequestBodyActionEnum().CREATE,
		Tags:   []ecs.BatchAddServerTag{{Key: "env", Value: ptr("prod")}, {Key: "owner", Value: ptr("sdk")}},
	}}); err != nil {
		t.Fatalf("BatchCreateServerTags: %v", err)
	}
	tags, err := compute.ShowServerTags(&ecs.ShowServerTagsRequest{ServerId: id})
	if err != nil || tags.Tags == nil || len(*tags.Tags) != 2 || (*tags.Tags)[0].Key != "env" ||
		(*tags.Tags)[0].Value == nil || *(*tags.Tags)[0].Value != "prod" {
		t.Fatalf("ShowServerTags = %+v, %v", tags, err)
	}
	project, err := compute.ListServerTags(&ecs.ListServerTagsRequest{})
	if err != nil || project.Tags == nil || len(*project.Tags) < 2 {
		t.Fatalf("ListServerTags = %+v, %v", project, err)
	}
	byTag, err := compute.ListServersDetails(&ecs.ListServersDetailsRequest{Tags: ptr("owner=sdk")})
	if err != nil || byTag.Count == nil || *byTag.Count != 1 || (*byTag.Servers)[0].Name != "ops-server-renamed" {
		t.Fatalf("ListServersDetails(tags) = %+v, %v", byTag, err)
	}
	if _, err := compute.BatchDeleteServerTags(&ecs.BatchDeleteServerTagsRequest{ServerId: id, Body: &ecs.BatchDeleteServerTagsRequestBody{
		Action: ecs.GetBatchDeleteServerTagsRequestBodyActionEnum().DELETE,
		Tags:   []ecs.ServerTag{{Key: "env"}},
	}}); err != nil {
		t.Fatalf("BatchDeleteServerTags: %v", err)
	}
	tags, err = compute.ShowServerTags(&ecs.ShowServerTagsRequest{ServerId: id})
	if err != nil || len(*tags.Tags) != 1 || (*tags.Tags)[0].Key != "owner" {
		t.Fatalf("tags after delete = %+v, %v", tags, err)
	}

	// --- Teardown ----------------------------------------------------------
	del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{Servers: servers}})
	waitJob("delete", del.JobId, err)
	if _, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID}); err != nil {
		t.Fatalf("DeleteSubnet: %v", err)
	}
	if _, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID}); err != nil {
		t.Fatalf("DeleteVpc: %v", err)
	}
}

func isPoolAddress(addr string) bool {
	return strings.HasPrefix(addr, "192.0.2.") ||
		strings.HasPrefix(addr, "198.51.100.") ||
		strings.HasPrefix(addr, "203.0.113.")
}

func floatingAddrs(srv *ecs.ServerDetail, vpcID string) []string {
	var out []string
	for _, a := range srv.Addresses[vpcID] {
		if a.OSEXTIPStype != nil && a.OSEXTIPStype.Value() == "floating" {
			out = append(out, a.Addr)
		}
	}
	return out
}

// TestServerEIPIntegration exercises the ECS-EIP link (§6) through the
// official ECS and EIP SDK clients:
//   - creating a server with a new EIP (delete_on_termination true and false);
//   - creating a server with an existing EIP ID;
//   - verifying ECS floating addresses match real pool EIPs;
//   - binding and unbinding an EIP after server creation and observing it in ECS;
//   - deleting servers with delete_publicip true vs false and delete_on_termination.
func TestServerEIPIntegration(t *testing.T) {
	net2 := newV2(t, realEndpoint)
	compute := newECS(t)
	images := newIMS(t)
	eips := newEIP(t)

	// --- Network & image setup ----------------------------------------
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("ecs-eip-vpc"), Cidr: ptr("10.62.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "ecs-eip VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "ecs-eip VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "ecs-eip-subnet", Cidr: "10.62.1.0/24", GatewayIp: "10.62.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "ecs-eip subnet to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "ecs-eip subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	listedImg, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || listedImg.Images == nil || len(*listedImg.Images) != 1 {
		t.Fatalf("ListImages: %+v, %v", listedImg, err)
	}
	imageID := (*listedImg.Images)[0].Id

	waitJob := func(what string, jobID *string, err error) {
		t.Helper()
		if err != nil || jobID == nil {
			t.Fatalf("%s: job %v, error %v", what, jobID, err)
		}
		eventually(t, what+" to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *jobID})
			if err != nil {
				t.Fatalf("ShowJob: %v", err)
			}
			if job.Status.Value() == "FAIL" {
				t.Fatalf("%s failed: %v", what, job.FailReason)
			}
			return job.Status.Value() == "SUCCESS"
		})
	}

	deleteServer := func(srvID string, deletePublicIP bool) {
		t.Helper()
		del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
			DeletePublicip: ptr(deletePublicIP),
			Servers:        []ecs.ServerId{{Id: srvID}},
		}})
		waitJob("delete server "+srvID, del.JobId, err)
	}

	findEIPByAddr := func(addr string) eip.PublicipShowResp {
		t.Helper()
		res, err := eips.ListPublicips(&eip.ListPublicipsRequest{PublicIpAddress: &[]string{addr}})
		if err != nil || res.Publicips == nil || len(*res.Publicips) != 1 {
			t.Fatalf("ListPublicips(addr=%s) = %+v, %v", addr, res, err)
		}
		return (*res.Publicips)[0]
	}

	// --- Case 1: New EIP with delete_on_termination=true --------------
	// Even when DeleteServers passes delete_publicip=false, the EIP must be
	// released because ReleaseWithPort was stored as true.
	ecsPer := ecs.GetPostPaidServerEipBandwidthSharetypeEnum().PER
	c1, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "ecs-eip-auto-del",
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			Publicip: &ecs.PostPaidServerPublicip{
				Eip: &ecs.PostPaidServerEip{
					Iptype: "5_bgp",
					Bandwidth: &ecs.PostPaidServerEipBandwidth{
						Sharetype:  ecsPer,
						Size:       ptr(int32(5)),
						Chargemode: ptr("bandwidth"),
					},
				},
				DeleteOnTermination: ptr(true),
			},
		},
	}})
	waitJob("create server with auto-delete EIP", c1.JobId, err)
	srv1ID := (*c1.ServerIds)[0]

	s1, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: srv1ID})
	if err != nil {
		t.Fatalf("ShowServer(1): %v", err)
	}
	floats1 := floatingAddrs(s1.Server, vpcID)
	if len(floats1) != 1 || !isPoolAddress(floats1[0]) {
		t.Fatalf("server 1 floating addresses = %v, want 1 pool IP", floats1)
	}
	pip1 := findEIPByAddr(floats1[0])
	pip1ID := *pip1.Id
	t.Cleanup(func() {
		_, _ = eips.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: pip1ID, Body: &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{}}})
		_, _ = eips.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pip1ID})
	})
	eventually(t, "server 1 EIP to become ACTIVE", func() bool {
		got, err := eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip1ID})
		return err == nil && got.Publicip.Status.Value() == "ACTIVE"
	})
	wantBWPrefix := "ecs-eip-auto-del-bandwidth-" + pip1ID[:4]
	if pip1.BandwidthName == nil || *pip1.BandwidthName != wantBWPrefix ||
		pip1.BandwidthSize == nil || *pip1.BandwidthSize != 5 ||
		pip1.BandwidthShareType == nil || pip1.BandwidthShareType.Value() != "PER" {
		t.Errorf("server 1 EIP bandwidth = name:%v size:%v share:%v, want %q 5 PER",
			pip1.BandwidthName, pip1.BandwidthSize, pip1.BandwidthShareType, wantBWPrefix)
	}

	// Delete with delete_publicip=false: delete_on_termination=true still releases the EIP.
	deleteServer(srv1ID, false)
	_, err = eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip1ID})
	wantError(t, err, 404, "VPC.0504")

	// --- Case 2: New EIP with delete_on_termination=false, kept on delete ---
	c2, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "ecs-eip-keep",
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			Publicip: &ecs.PostPaidServerPublicip{
				Eip: &ecs.PostPaidServerEip{
					Iptype: "5_bgp",
					Bandwidth: &ecs.PostPaidServerEipBandwidth{
						Sharetype: ecsPer,
						Size:      ptr(int32(6)),
					},
				},
				DeleteOnTermination: ptr(false),
			},
		},
	}})
	waitJob("create server with kept EIP", c2.JobId, err)
	srv2ID := (*c2.ServerIds)[0]

	s2, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: srv2ID})
	if err != nil {
		t.Fatalf("ShowServer(2): %v", err)
	}
	floats2 := floatingAddrs(s2.Server, vpcID)
	if len(floats2) != 1 || !isPoolAddress(floats2[0]) {
		t.Fatalf("server 2 floating addresses = %v, want 1 pool IP", floats2)
	}
	pip2 := findEIPByAddr(floats2[0])
	pip2ID := *pip2.Id
	pip2Addr := *pip2.PublicIpAddress
	t.Cleanup(func() {
		_, _ = eips.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: pip2ID, Body: &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{}}})
		_, _ = eips.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pip2ID})
	})
	eventually(t, "server 2 EIP to become ACTIVE", func() bool {
		got, err := eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip2ID})
		return err == nil && got.Publicip.Status.Value() == "ACTIVE"
	})

	// Delete with delete_publicip=false: EIP survives and is unbound (DOWN).
	deleteServer(srv2ID, false)
	keptPIP, err := eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip2ID})
	if err != nil || keptPIP.Publicip == nil ||
		keptPIP.Publicip.Status.Value() != "DOWN" || keptPIP.Publicip.PortId != nil {
		t.Fatalf("EIP after delete(delete_publicip=false) = %+v, %v; want DOWN and unbound", keptPIP, err)
	}

	// --- Case 3: Create server with existing EIP ID, delete with delete_publicip=true ---
	c3, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "ecs-eip-existing",
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			Publicip:   &ecs.PostPaidServerPublicip{Id: &pip2ID},
		},
	}})
	waitJob("create server with existing EIP", c3.JobId, err)
	srv3ID := (*c3.ServerIds)[0]

	s3, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: srv3ID})
	if err != nil {
		t.Fatalf("ShowServer(3): %v", err)
	}
	floats3 := floatingAddrs(s3.Server, vpcID)
	if len(floats3) != 1 || floats3[0] != pip2Addr {
		t.Fatalf("server 3 floating addresses = %v, want [%s]", floats3, pip2Addr)
	}
	boundPIP, err := eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip2ID})
	if err != nil || boundPIP.Publicip == nil ||
		boundPIP.Publicip.Status.Value() != "ACTIVE" || boundPIP.Publicip.PortId == nil {
		t.Fatalf("existing EIP after attach = %+v, %v; want ACTIVE and bound", boundPIP, err)
	}

	// Delete with delete_publicip=true: releases the existing EIP too.
	deleteServer(srv3ID, true)
	_, err = eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip2ID})
	wantError(t, err, 404, "VPC.0504")

	// --- Case 4: Bind an EIP after server creation, observe in ECS ----
	c4, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "ecs-eip-post-bind",
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
		},
	}})
	waitJob("create server without EIP", c4.JobId, err)
	srv4ID := (*c4.ServerIds)[0]
	t.Cleanup(func() {
		del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
			Servers: []ecs.ServerId{{Id: srv4ID}},
		}})
		if err == nil && del.JobId != nil {
			eventually(t, "cleanup server 4", func() bool {
				job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: *del.JobId})
				return err == nil && job.Status != nil && job.Status.Value() == "SUCCESS"
			})
		}
	})

	s4Before, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: srv4ID})
	if err != nil {
		t.Fatalf("ShowServer(4 before bind): %v", err)
	}
	if got := floatingAddrs(s4Before.Server, vpcID); len(got) != 0 {
		t.Fatalf("server 4 floating addresses before bind = %v, want empty", got)
	}

	ports4, err := net2.ListPorts(&v2.ListPortsRequest{DeviceId: &srv4ID})
	if err != nil || ports4.Ports == nil || len(*ports4.Ports) != 1 {
		t.Fatalf("ListPorts(4) = %+v, %v", ports4, err)
	}
	port4ID := (*ports4.Ports)[0].Id

	perShare := eip.GetCreatePublicipBandwidthOptionShareTypeEnum().PER
	createdPIP, err := eips.CreatePublicip(&eip.CreatePublicipRequest{Body: &eip.CreatePublicipRequestBody{
		Publicip:  &eip.CreatePublicipOption{Type: "5_bgp", Alias: ptr("ecs-post-bind-eip")},
		Bandwidth: &eip.CreatePublicipBandwidthOption{Name: ptr("ecs-post-bind-bw"), ShareType: perShare, Size: ptr(int32(5))},
	}})
	if err != nil || createdPIP.Publicip == nil || createdPIP.Publicip.Id == nil {
		t.Fatalf("CreatePublicip(post-bind): %+v, %v", createdPIP, err)
	}
	pip4ID := *createdPIP.Publicip.Id
	pip4Addr := *createdPIP.Publicip.PublicIpAddress
	t.Cleanup(func() {
		_, _ = eips.UpdatePublicip(&eip.UpdatePublicipRequest{PublicipId: pip4ID, Body: &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{}}})
		_, _ = eips.DeletePublicip(&eip.DeletePublicipRequest{PublicipId: pip4ID})
	})
	eventually(t, "post-bind EIP to become DOWN", func() bool {
		got, err := eips.ShowPublicip(&eip.ShowPublicipRequest{PublicipId: pip4ID})
		return err == nil && got.Publicip.Status.Value() == "DOWN"
	})

	if _, err := eips.UpdatePublicip(&eip.UpdatePublicipRequest{
		PublicipId: pip4ID,
		Body:       &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{PortId: &port4ID}},
	}); err != nil {
		t.Fatalf("UpdatePublicip(bind to server 4): %v", err)
	}

	s4Bound, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: srv4ID})
	if err != nil {
		t.Fatalf("ShowServer(4 after bind): %v", err)
	}
	if got := floatingAddrs(s4Bound.Server, vpcID); len(got) != 1 || got[0] != pip4Addr {
		t.Fatalf("server 4 floating addresses after bind = %v, want [%s]", got, pip4Addr)
	}

	if _, err := eips.UpdatePublicip(&eip.UpdatePublicipRequest{
		PublicipId: pip4ID,
		Body:       &eip.UpdatePublicipsRequestBody{Publicip: &eip.UpdatePublicipOption{PortId: ptr("")}},
	}); err != nil {
		t.Fatalf("UpdatePublicip(unbind from server 4): %v", err)
	}

	s4Unbound, err := compute.ShowServer(&ecs.ShowServerRequest{ServerId: srv4ID})
	if err != nil {
		t.Fatalf("ShowServer(4 after unbind): %v", err)
	}
	if got := floatingAddrs(s4Unbound.Server, vpcID); len(got) != 0 {
		t.Fatalf("server 4 floating addresses after unbind = %v, want empty", got)
	}

	// --- Case 5: Error path - unknown existing EIP ID fails create ----
	_, err = compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:       "ecs-eip-bad-id",
			ImageRef:   imageID,
			FlavorRef:  "s6.large.2",
			Vpcid:      vpcID,
			Nics:       []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume: &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().SSD},
			Publicip:   &ecs.PostPaidServerPublicip{Id: ptr(unknownID)},
		},
	}})
	wantError(t, err, 400, "Ecs.0005")
}
