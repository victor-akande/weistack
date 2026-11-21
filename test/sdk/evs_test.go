package sdk

import (
	"testing"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	evsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2"
	evs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

func evsStr(s string) *string { return &s }

const evsEndpoint = "http://evs." + region + ".myhuaweicloud.com"

func newEVS(t *testing.T) *evsv2.EvsClient {
	t.Helper()
	return evsAs(t, signingAK("AKEVSSDKEXAMPLE00000"), signingSK())
}

func evsAs(t *testing.T, ak, sk string) *evsv2.EvsClient {
	t.Helper()
	cred, err := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		t.Fatalf("building credentials: %v", err)
	}
	hc, err := evsv2.EvsClientBuilder().
		WithEndpoints([]string{evsEndpoint}).
		WithCredential(cred).
		WithHttpConfig(httpConfigAt(emulatorAddr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building EVS client: %v", err)
	}
	return evsv2.NewEvsClient(hc)
}

func waitEVSJob(t *testing.T, c *evsv2.EvsClient, jobID string) *evs.ShowJobResponse {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res, err := c.ShowJob(&evs.ShowJobRequest{JobId: jobID})
		if err != nil {
			t.Fatalf("ShowJob(%s): %v", jobID, err)
		}
		if res.Status != nil && *res.Status != evs.GetShowJobResponseStatusEnum().RUNNING {
			if *res.Status != evs.GetShowJobResponseStatusEnum().SUCCESS {
				t.Fatalf("EVS job %s ended with %v", jobID, res)
			}
			return res
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for EVS job %s", jobID)
	return nil
}

func TestEVSTypesAndZones(t *testing.T) {
	t.Parallel()
	c := newEVS(t)

	typesRes, err := c.CinderListVolumeTypes(&evs.CinderListVolumeTypesRequest{})
	if err != nil || typesRes.VolumeTypes == nil || len(*typesRes.VolumeTypes) != 7 {
		t.Fatalf("CinderListVolumeTypes: %+v, %v", typesRes, err)
	}

	azRes, err := c.CinderListAvailabilityZones(&evs.CinderListAvailabilityZonesRequest{})
	if err != nil || azRes.AvailabilityZoneInfo == nil || len(*azRes.AvailabilityZoneInfo) == 0 {
		t.Fatalf("CinderListAvailabilityZones: %+v, %v", azRes, err)
	}
}

func TestEVSVolumeLifecycleAndTags(t *testing.T) {
	t.Parallel()
	c := newEVS(t)

	azRes, err := c.CinderListAvailabilityZones(&evs.CinderListAvailabilityZonesRequest{})
	if err != nil || azRes.AvailabilityZoneInfo == nil || len(*azRes.AvailabilityZoneInfo) == 0 {
		t.Fatalf("CinderListAvailabilityZones: %v", err)
	}
	az := (*azRes.AvailabilityZoneInfo)[0].ZoneName

	name := "sdk-vol"
	desc := "initial desc"
	volType := evs.GetCreateVolumeOptionVolumeTypeEnum().GPSSD
	cr, err := c.CreateVolume(&evs.CreateVolumeRequest{
		Body: &evs.CreateVolumeRequestBody{
			Volume: &evs.CreateVolumeOption{
				AvailabilityZone: az,
				Name:             &name,
				Description:      &desc,
				Size:             20,
				VolumeType:       volType,
				Tags:             map[string]string{"env": "dev"},
			},
		},
	})
	if err != nil || cr.JobId == nil || cr.VolumeIds == nil || len(*cr.VolumeIds) != 1 {
		t.Fatalf("CreateVolume: %+v, %v", cr, err)
	}
	volID := (*cr.VolumeIds)[0]
	waitEVSJob(t, c, *cr.JobId)

	// Show and List.
	show, err := c.ShowVolume(&evs.ShowVolumeRequest{VolumeId: volID})
	if err != nil || show.Volume == nil || show.Volume.Status != "available" || show.Volume.Size != 20 {
		t.Fatalf("ShowVolume: %+v, %v", show, err)
	}
	list, err := c.ListVolumes(&evs.ListVolumesRequest{Name: &name})
	if err != nil || list.Volumes == nil || len(*list.Volumes) == 0 {
		t.Fatalf("ListVolumes: %+v, %v", list, err)
	}

	// Update.
	newName := "sdk-vol-renamed"
	newDesc := "updated desc"
	upd, err := c.UpdateVolume(&evs.UpdateVolumeRequest{
		VolumeId: volID,
		Body: &evs.UpdateVolumeRequestBody{
			Volume: &evs.UpdateVolumeOption{Name: &newName, Description: &newDesc},
		},
	})
	if err != nil || upd.Name == nil || *upd.Name != newName {
		t.Fatalf("UpdateVolume: %+v, %v", upd, err)
	}

	// Tags.
	if _, err := c.BatchCreateVolumeTags(&evs.BatchCreateVolumeTagsRequest{
		VolumeId: volID,
		Body: &evs.BatchCreateVolumeTagsRequestBody{
			Action: evs.GetBatchCreateVolumeTagsRequestBodyActionEnum().CREATE,
			Tags:   []evs.Tag{{Key: "team", Value: "core"}},
		},
	}); err != nil {
		t.Fatalf("BatchCreateVolumeTags: %v", err)
	}
	tagsRes, err := c.ShowVolumeTags(&evs.ShowVolumeTagsRequest{VolumeId: volID})
	if err != nil || tagsRes.Tags == nil || len(*tagsRes.Tags) != 2 || (*tagsRes.Tags)[1].Key != "team" || (*tagsRes.Tags)[1].Value != "core" {
		t.Fatalf("ShowVolumeTags: %+v, %v", tagsRes, err)
	}
	allTags, err := c.ListVolumeTags(&evs.ListVolumeTagsRequest{})
	if err != nil || len(allTags.Tags["team"]) == 0 {
		t.Fatalf("ListVolumeTags: %+v, %v", allTags, err)
	}
	if _, err := c.BatchDeleteVolumeTags(&evs.BatchDeleteVolumeTagsRequest{
		VolumeId: volID,
		Body: &evs.BatchDeleteVolumeTagsRequestBody{
			Action: evs.GetBatchDeleteVolumeTagsRequestBodyActionEnum().DELETE,
			Tags:   []evs.DeleteTagsOption{{Key: "team"}},
		},
	}); err != nil {
		t.Fatalf("BatchDeleteVolumeTags: %v", err)
	}

	// Resize.
	resz, err := c.ResizeVolume(&evs.ResizeVolumeRequest{
		VolumeId: volID,
		Body: &evs.ResizeVolumeRequestBody{
			OsExtend: &evs.OsExtend{NewSize: 30},
		},
	})
	if err != nil || resz.JobId == nil {
		t.Fatalf("ResizeVolume: %+v, %v", resz, err)
	}
	waitEVSJob(t, c, *resz.JobId)
	afterResize, err := c.ShowVolume(&evs.ShowVolumeRequest{VolumeId: volID})
	if err != nil || afterResize.Volume.Size != 30 {
		t.Fatalf("ShowVolume after resize: %+v, %v", afterResize, err)
	}

	// Delete.
	del, err := c.DeleteVolume(&evs.DeleteVolumeRequest{VolumeId: volID})
	if err != nil || del.JobId == nil {
		t.Fatalf("DeleteVolume: %+v, %v", del, err)
	}
	waitEVSJob(t, c, *del.JobId)
	if _, err := c.ShowVolume(&evs.ShowVolumeRequest{VolumeId: volID}); err == nil {
		t.Fatal("ShowVolume after DeleteVolume succeeded")
	}
}

func TestEVSECSAttachDetachAndBlockDevice(t *testing.T) {
	t.Parallel()
	c := newEVS(t)
	compute := newECS(t)
	netClient := newV2(t, "http://vpc."+region+".myhuaweicloud.com")

	vpcRes, err := netClient.CreateVpc(&v2.CreateVpcRequest{
		Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{Name: evsStr("sdk-evs-vpc"), Cidr: evsStr("10.120.0.0/16")}},
	})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vpcRes.Vpc.Id
	defer func() { _, _ = netClient.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID}) }()

	snRes, err := netClient.CreateSubnet(&v2.CreateSubnetRequest{
		Body: &v2.CreateSubnetRequestBody{
			Subnet: &v2.CreateSubnetOption{
				Name: "sdk-evs-sn", Cidr: "10.120.1.0/24", GatewayIp: "10.120.1.1", VpcId: vpcID,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	snID := snRes.Subnet.Id
	defer func() { _, _ = netClient.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: snID}) }()

	azRes, err := c.CinderListAvailabilityZones(&evs.CinderListAvailabilityZonesRequest{})
	if err != nil || azRes.AvailabilityZoneInfo == nil || len(*azRes.AvailabilityZoneInfo) == 0 {
		t.Fatalf("CinderListAvailabilityZones: %v", err)
	}
	az := (*azRes.AvailabilityZoneInfo)[0].ZoneName

	waitECSJob := func(jobID string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			res, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: jobID})
			if err != nil {
				t.Fatalf("ECS ShowJob(%s): %v", jobID, err)
			}
			if res.Status != nil && *res.Status != ecs.GetShowJobResponseStatusEnum().RUNNING {
				if *res.Status != ecs.GetShowJobResponseStatusEnum().SUCCESS {
					t.Fatalf("ECS job %s ended with %v", jobID, res)
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for ECS job %s", jobID)
	}

	srvRes, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{
		Body: &ecs.CreatePostPaidServersRequestBody{
			Server: &ecs.PostPaidServer{
				Name:             "sdk-evs-srv",
				ImageRef:         "455b5860-f96d-5d89-baaa-ec6adb758c5b",
				FlavorRef:        "s6.large.2",
				Vpcid:            vpcID,
				AvailabilityZone: &az,
				Nics:             []ecs.PostPaidServerNic{{SubnetId: &snID}},
				RootVolume:       &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().GPSSD},
			},
		},
	})
	if err != nil || srvRes.JobId == nil || srvRes.ServerIds == nil || len(*srvRes.ServerIds) != 1 {
		t.Fatalf("CreateServers: %+v, %v", srvRes, err)
	}
	srvID := (*srvRes.ServerIds)[0]
	waitECSJob(*srvRes.JobId)

	// Create standalone data disk.
	volName := "sdk-attach-vol"
	crVol, err := c.CreateVolume(&evs.CreateVolumeRequest{
		Body: &evs.CreateVolumeRequestBody{
			Volume: &evs.CreateVolumeOption{
				AvailabilityZone: az,
				Name:             &volName,
				Size:             15,
				VolumeType:       evs.GetCreateVolumeOptionVolumeTypeEnum().GPSSD,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	volID := (*crVol.VolumeIds)[0]
	waitEVSJob(t, c, *crVol.JobId)

	// DryRun attach.
	dry := true
	if _, err := compute.AttachServerVolume(&ecs.AttachServerVolumeRequest{
		ServerId: srvID,
		Body: &ecs.AttachServerVolumeRequestBody{
			VolumeAttachment: &ecs.AttachServerVolumeOption{VolumeId: volID},
			DryRun:           &dry,
		},
	}); err != nil {
		t.Fatalf("AttachServerVolume dry_run: %v", err)
	}

	// Real attach.
	att, err := compute.AttachServerVolume(&ecs.AttachServerVolumeRequest{
		ServerId: srvID,
		Body: &ecs.AttachServerVolumeRequestBody{
			VolumeAttachment: &ecs.AttachServerVolumeOption{VolumeId: volID},
		},
	})
	if err != nil || att.JobId == nil {
		t.Fatalf("AttachServerVolume: %+v, %v", att, err)
	}
	waitECSJob(*att.JobId)

	// Block device list & show.
	bds, err := compute.ListServerBlockDevices(&ecs.ListServerBlockDevicesRequest{ServerId: srvID})
	if err != nil || bds.VolumeAttachments == nil || len(*bds.VolumeAttachments) != 2 {
		t.Fatalf("ListServerBlockDevices: %+v, %v", bds, err)
	}
	bd, err := compute.ShowServerBlockDevice(&ecs.ShowServerBlockDeviceRequest{ServerId: srvID, VolumeId: volID})
	if err != nil || bd.VolumeAttachment == nil || *bd.VolumeAttachment.VolumeId != volID {
		t.Fatalf("ShowServerBlockDevice: %+v, %v", bd, err)
	}

	// Update delete_on_termination.
	if _, err := compute.UpdateServerBlockDevice(&ecs.UpdateServerBlockDeviceRequest{
		ServerId: srvID,
		VolumeId: volID,
		Body: &ecs.UpdateServerBlockDeviceReq{
			BlockDevice: &ecs.UpdateServerBlockDeviceOption{DeleteOnTermination: true},
		},
	}); err != nil {
		t.Fatalf("UpdateServerBlockDevice: %v", err)
	}

	// Detach.
	det, err := compute.DetachServerVolume(&ecs.DetachServerVolumeRequest{ServerId: srvID, VolumeId: volID})
	if err != nil || det.JobId == nil {
		t.Fatalf("DetachServerVolume: %+v, %v", det, err)
	}
	waitECSJob(*det.JobId)

	afterDetach, err := c.ShowVolume(&evs.ShowVolumeRequest{VolumeId: volID})
	if err != nil || afterDetach.Volume.Status != "available" {
		t.Fatalf("ShowVolume after detach: %+v, %v", afterDetach, err)
	}

	// Re-attach (delete_on_termination defaults to false) and delete server: data disk survives as available.
	att2, err := compute.AttachServerVolume(&ecs.AttachServerVolumeRequest{
		ServerId: srvID,
		Body: &ecs.AttachServerVolumeRequestBody{
			VolumeAttachment: &ecs.AttachServerVolumeOption{VolumeId: volID},
		},
	})
	if err != nil || att2.JobId == nil {
		t.Fatalf("AttachServerVolume(2): %+v, %v", att2, err)
	}
	waitECSJob(*att2.JobId)

	delSrv, err := compute.DeleteServers(&ecs.DeleteServersRequest{
		Body: &ecs.DeleteServersRequestBody{
			Servers: []ecs.ServerId{{Id: srvID}},
		},
	})
	if err != nil || delSrv.JobId == nil {
		t.Fatalf("DeleteServers: %+v, %v", delSrv, err)
	}
	waitECSJob(*delSrv.JobId)

	survived, err := c.ShowVolume(&evs.ShowVolumeRequest{VolumeId: volID})
	if err != nil || survived.Volume.Status != "available" {
		t.Fatalf("data disk after server delete = %+v, %v; want available", survived, err)
	}

	delVol, err := c.DeleteVolume(&evs.DeleteVolumeRequest{VolumeId: volID})
	if err != nil {
		t.Fatalf("DeleteVolume: %v", err)
	}
	waitEVSJob(t, c, *delVol.JobId)
}

// TestEVSPermissions runs only with WEISTACK_SDK_IAM=enforce (§7): a user
// holding only evs:volumes:list can list volumes and is refused
// CreateVolume with 403 WeiStack.0403.
func TestEVSPermissions(t *testing.T) {
	if !enforcing {
		t.Skip("set WEISTACK_SDK_IAM=enforce")
	}
	t.Parallel()
	admin, admin5 := iamClientsAs(t, adminAK, adminSK)

	u, err := admin5.CreateUserV5(&v5.CreateUserV5Request{Body: &v5.CreateUserReqBody{Name: "sdk-evs-limited", Enabled: true}})
	if err != nil {
		t.Fatalf("CreateUserV5: %v", err)
	}
	uid := u.User.UserId
	defer func() {
		if _, err := admin5.DeleteUserV5(&v5.DeleteUserV5Request{UserId: uid}); err != nil {
			t.Errorf("DeleteUserV5: %v", err)
		}
	}()

	key, err := admin.CreatePermanentAccessKey(&iam.CreatePermanentAccessKeyRequest{Body: &iam.CreatePermanentAccessKeyRequestBody{
		Credential: &iam.CreateCredentialOption{UserId: uid},
	}})
	if err != nil {
		t.Fatalf("CreatePermanentAccessKey: %v", err)
	}
	ak, sk := key.Credential.Access, key.Credential.Secret

	role, err := admin.CreateCloudServiceCustomPolicy(&iam.CreateCloudServiceCustomPolicyRequest{
		Body: &iam.CreateCloudServiceCustomPolicyRequestBody{Role: &iam.ServicePolicyRoleOption{
			DisplayName: "sdk-evs-list-only",
			Type:        "AX",
			Description: "evs:volumes:list only",
			Policy: &iam.ServicePolicy{
				Version: "1.1",
				Statement: []iam.ServiceStatement{{
					Action: []string{"evs:volumes:list"},
					Effect: iam.GetServiceStatementEffectEnum().ALLOW,
				}},
			},
		}},
	})
	if err != nil || role.Role == nil {
		t.Fatalf("CreateCloudServiceCustomPolicy: %+v, %v", role, err)
	}
	roleID := role.Role.Id
	defer func() {
		if _, err := admin.DeletePermanentAccessKey(&iam.DeletePermanentAccessKeyRequest{AccessKey: ak}); err != nil {
			t.Errorf("DeletePermanentAccessKey: %v", err)
		}
		if _, err := admin.DeleteCustomPolicy(&iam.DeleteCustomPolicyRequest{RoleId: roleID}); err != nil {
			t.Errorf("DeleteCustomPolicy: %v", err)
		}
	}()

	g, err := admin.KeystoneCreateGroup(&iam.KeystoneCreateGroupRequest{Body: &iam.KeystoneCreateGroupRequestBody{
		Group: &iam.KeystoneCreateGroupOption{Name: "sdk-evs-readers"},
	}})
	if err != nil {
		t.Fatalf("KeystoneCreateGroup: %v", err)
	}
	gid := g.Group.Id
	defer func() {
		if _, err := admin.KeystoneDeleteGroup(&iam.KeystoneDeleteGroupRequest{GroupId: gid}); err != nil {
			t.Errorf("KeystoneDeleteGroup: %v", err)
		}
	}()
	if _, err := admin.KeystoneAddUserToGroup(&iam.KeystoneAddUserToGroupRequest{GroupId: gid, UserId: uid}); err != nil {
		t.Fatalf("KeystoneAddUserToGroup: %v", err)
	}
	if _, err := admin.KeystoneAssociateGroupWithProjectPermission(&iam.KeystoneAssociateGroupWithProjectPermissionRequest{
		ProjectId: projectID, GroupId: gid, RoleId: roleID,
	}); err != nil {
		t.Fatalf("KeystoneAssociateGroupWithProjectPermission: %v", err)
	}

	limited := evsAs(t, ak, sk)
	if _, err := limited.ListVolumes(&evs.ListVolumesRequest{}); err != nil {
		t.Fatalf("limited ListVolumes: %v", err)
	}

	_, err = limited.CreateVolume(&evs.CreateVolumeRequest{
		Body: &evs.CreateVolumeRequestBody{
			Volume: &evs.CreateVolumeOption{
				AvailabilityZone: "ap-southeast-1a",
				Size:             10,
				VolumeType:       evs.GetCreateVolumeOptionVolumeTypeEnum().GPSSD,
			},
		},
	})
	denialOf(t, err, "WeiStack.0403")
}
