package sdk

import (
	"testing"

	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	eip "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/eip/v2/model"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/model"
	evs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/evs/v2/model"
	iam "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v3/model"
	v5 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/iam/v5/model"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	v3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
)

// TestQuotaVPCAndEIP exercises VPC v2 ShowQuota, EIP v2 ListQuotas, and
// VPC v3 ShowQuota, verifying resource ordering, type filtering, invalid
// type handling, cross-version consistency, and live usage tracking.
func TestQuotaVPCAndEIP(t *testing.T) {
	net2 := newV2(t, realEndpoint)
	net3 := newV3(t)
	eipClient := newEIP(t)

	// Unfiltered VPC v2 ShowQuota returns all 9 resource types in order.
	all, err := net2.ShowQuota(&v2.ShowQuotaRequest{})
	if err != nil || all.Quotas == nil {
		t.Fatalf("vpc/v2 ShowQuota: %+v, %v", all, err)
	}
	wantOrder := []string{
		"vpc", "subnet", "securityGroup", "securityGroupRule",
		"publicIp", "shareBandwidth", "shareBandwidthIP",
		"loadbalancer", "listener",
	}
	if len(all.Quotas.Resources) != len(wantOrder) {
		t.Fatalf("vpc/v2 ShowQuota returned %d resources, want %d: %+v", len(all.Quotas.Resources), len(wantOrder), all.Quotas.Resources)
	}
	v2ByType := make(map[string]v2.ResourceResult, len(wantOrder))
	for i, wantType := range wantOrder {
		r := all.Quotas.Resources[i]
		if r.Type.Value() != wantType {
			t.Errorf("resource[%d].Type = %q, want %q", i, r.Type.Value(), wantType)
		}
		if r.Min != 0 {
			t.Errorf("%s: Min = %d, want 0", wantType, r.Min)
		}
		if r.Used < 0 {
			t.Errorf("%s: Used = %d, want >= 0", wantType, r.Used)
		}
		if r.Quota <= 0 && r.Quota != -1 {
			t.Errorf("%s: Quota = %d, want > 0 or -1", wantType, r.Quota)
		}
		v2ByType[r.Type.Value()] = r
	}

	// Filter by type: vpc, publicIp, loadbalancer.
	enum := v2.GetShowQuotaRequestTypeEnum()
	for _, tc := range []struct {
		typ  v2.ShowQuotaRequestType
		name string
	}{
		{enum.VPC, "vpc"},
		{enum.PUBLIC_IP, "publicIp"},
		{enum.LOADBALANCER, "loadbalancer"},
	} {
		res, err := net2.ShowQuota(&v2.ShowQuotaRequest{Type: &tc.typ})
		if err != nil || res.Quotas == nil || len(res.Quotas.Resources) != 1 {
			t.Fatalf("vpc/v2 ShowQuota(type=%s) = %+v, %v", tc.name, res, err)
		}
		got := res.Quotas.Resources[0]
		if got.Type.Value() != tc.name || got.Quota != v2ByType[tc.name].Quota || got.Min != 0 {
			t.Errorf("vpc/v2 ShowQuota(type=%s) = %+v, want matching %+v", tc.name, got, v2ByType[tc.name])
		}
	}

	// Unknown type returns 400 VPC.1207.
	var badType v2.ShowQuotaRequestType
	if err := badType.UnmarshalJSON([]byte(`"notARealQuotaType"`)); err != nil {
		t.Fatalf("UnmarshalJSON badType: %v", err)
	}
	_, err = net2.ShowQuota(&v2.ShowQuotaRequest{Type: &badType})
	wantError(t, err, 400, "VPC.1207")

	// Live usage tracking: creating and deleting a VPC increments/decrements used.
	beforeVPC := v2ByType["vpc"].Used
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("sdk-quota-vpc"), Cidr: ptr("10.95.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	vpcDeleted := false
	t.Cleanup(func() {
		if vpcDeleted {
			return
		}
		eventually(t, "quota VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "quota VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	afterCreate, err := net2.ShowQuota(&v2.ShowQuotaRequest{Type: &enum.VPC})
	if err != nil || afterCreate.Quotas == nil || len(afterCreate.Quotas.Resources) != 1 {
		t.Fatalf("ShowQuota after create: %+v, %v", afterCreate, err)
	}
	if afterCreate.Quotas.Resources[0].Used != beforeVPC+1 {
		t.Fatalf("vpc used after create = %d, want %d", afterCreate.Quotas.Resources[0].Used, beforeVPC+1)
	}

	if _, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID}); err != nil {
		t.Fatalf("DeleteVpc: %v", err)
	}
	vpcDeleted = true

	afterDelete, err := net2.ShowQuota(&v2.ShowQuotaRequest{Type: &enum.VPC})
	if err != nil || afterDelete.Quotas == nil || len(afterDelete.Quotas.Resources) != 1 {
		t.Fatalf("ShowQuota after delete: %+v, %v", afterDelete, err)
	}
	if afterDelete.Quotas.Resources[0].Used != beforeVPC {
		t.Fatalf("vpc used after delete = %d, want %d", afterDelete.Quotas.Resources[0].Used, beforeVPC)
	}

	// EIP v2 ListQuotas calls GET /v1/{project_id}/quotas and sees EIP quotas.
	eipAll, err := eipClient.ListQuotas(&eip.ListQuotasRequest{})
	if err != nil || eipAll.Quotas == nil {
		t.Fatalf("eip/v2 ListQuotas: %+v, %v", eipAll, err)
	}
	eipByType := make(map[string]eip.QuotaShowResp, len(eipAll.Quotas.Resources))
	for _, r := range eipAll.Quotas.Resources {
		if r.Type != nil {
			eipByType[*r.Type] = r
		}
	}
	for _, k := range []string{"publicIp", "shareBandwidth", "shareBandwidthIP"} {
		r, ok := eipByType[k]
		if !ok {
			t.Fatalf("eip/v2 ListQuotas missing %q", k)
		}
		if r.Quota == nil || *r.Quota != v2ByType[k].Quota || r.Used == nil || *r.Used < 0 || r.Min == nil || *r.Min != 0 {
			t.Errorf("eip/v2 ListQuotas[%s] = %+v, want quota %d min 0", k, r, v2ByType[k].Quota)
		}
	}
	eipFiltered, err := eipClient.ListQuotas(&eip.ListQuotasRequest{Type: ptr("publicIp")})
	if err != nil || eipFiltered.Quotas == nil || len(eipFiltered.Quotas.Resources) != 1 ||
		eipFiltered.Quotas.Resources[0].Type == nil || *eipFiltered.Quotas.Resources[0].Type != "publicIp" {
		t.Fatalf("eip/v2 ListQuotas(type=publicIp) = %+v, %v", eipFiltered, err)
	}

	// VPC v3 ShowQuota matches v2 limits for the 4 emulated fields and omits unemulated ones.
	v3Res, err := net3.ShowQuota(&v3.ShowQuotaRequest{})
	if err != nil || v3Res.Quota == nil {
		t.Fatalf("vpc/v3 ShowQuota: %+v, %v", v3Res, err)
	}
	q3 := v3Res.Quota
	if q3.Vpc == nil || *q3.Vpc != v2ByType["vpc"].Quota {
		t.Errorf("vpc/v3 Quota.Vpc = %v, want %d", q3.Vpc, v2ByType["vpc"].Quota)
	}
	if q3.Virsubnet == nil || *q3.Virsubnet != v2ByType["subnet"].Quota {
		t.Errorf("vpc/v3 Quota.Virsubnet = %v, want %d", q3.Virsubnet, v2ByType["subnet"].Quota)
	}
	if q3.SecurityGroup == nil || *q3.SecurityGroup != v2ByType["securityGroup"].Quota {
		t.Errorf("vpc/v3 Quota.SecurityGroup = %v, want %d", q3.SecurityGroup, v2ByType["securityGroup"].Quota)
	}
	if q3.SecurityGroupRule == nil || *q3.SecurityGroupRule != v2ByType["securityGroupRule"].Quota {
		t.Errorf("vpc/v3 Quota.SecurityGroupRule = %v, want %d", q3.SecurityGroupRule, v2ByType["securityGroupRule"].Quota)
	}
	if q3.Peering != nil {
		t.Errorf("vpc/v3 Quota.Peering = %v, want nil (unemulated)", *q3.Peering)
	}
}

// TestQuotaELB exercises ELB v3 ShowQuota and ListQuotaDetails, checking
// emulated and unemulated fields, repeatable quota_key filtering, and
// usage tracking when creating/deleting a certificate.
func TestQuotaELB(t *testing.T) {
	c := newELB(t)

	shown, err := c.ShowQuota(&elb.ShowQuotaRequest{})
	if err != nil || shown.Quota == nil {
		t.Fatalf("elb/v3 ShowQuota: %+v, %v", shown, err)
	}
	if shown.RequestId == nil || *shown.RequestId == "" {
		t.Errorf("elb/v3 ShowQuota missing request_id")
	}
	q := shown.Quota
	if q.ProjectId != projectID {
		t.Errorf("Quota.ProjectId = %q, want %q", q.ProjectId, projectID)
	}

	emulated := []struct {
		key string
		val int32
	}{
		{"loadbalancer", q.Loadbalancer},
		{"listener", q.Listener},
		{"l7policy", q.L7policy},
		{"pool", q.Pool},
		{"member", q.Member},
		{"certificate", q.Certificate},
		{"l7policies_per_listener", q.L7policiesPerListener},
	}
	wantLimit := make(map[string]int32, len(emulated))
	for _, e := range emulated {
		if e.val <= 0 && e.val != -1 {
			t.Errorf("ShowQuota.%s = %d, want > 0 or -1", e.key, e.val)
		}
		wantLimit[e.key] = e.val
	}

	unemulated := []struct {
		name string
		val  int32
	}{
		{"condition_per_policy", q.ConditionPerPolicy},
		{"healthmonitor", q.Healthmonitor},
		{"members_per_pool", q.MembersPerPool},
		{"listeners_per_pool", q.ListenersPerPool},
		{"ipgroup", q.Ipgroup},
		{"ipgroup_bindings", q.IpgroupBindings},
		{"ipgroup_max_length", q.IpgroupMaxLength},
		{"ipgroups_per_listener", q.IpgroupsPerListener},
		{"security_policy", q.SecurityPolicy},
		{"listeners_per_loadbalancer", q.ListenersPerLoadbalancer},
		{"pools_per_l7policy", q.PoolsPerL7policy},
		{"free_instance_members_per_pool", q.FreeInstanceMembersPerPool},
		{"free_instance_listeners_per_loadbalancer", q.FreeInstanceListenersPerLoadbalancer},
	}
	for _, u := range unemulated {
		if u.val != -1 {
			t.Errorf("ShowQuota.%s = %d, want -1", u.name, u.val)
		}
	}

	// ListQuotaDetails unfiltered returns all 7 keys in order.
	details, err := c.ListQuotaDetails(&elb.ListQuotaDetailsRequest{})
	if err != nil || details.Quotas == nil {
		t.Fatalf("elb/v3 ListQuotaDetails: %+v, %v", details, err)
	}
	if len(*details.Quotas) != len(emulated) {
		t.Fatalf("ListQuotaDetails returned %d items, want %d: %+v", len(*details.Quotas), len(emulated), *details.Quotas)
	}
	for i, e := range emulated {
		got := (*details.Quotas)[i]
		if got.QuotaKey != e.key {
			t.Errorf("details[%d].QuotaKey = %q, want %q", i, got.QuotaKey, e.key)
		}
		if got.QuotaLimit != wantLimit[e.key] {
			t.Errorf("details[%s].QuotaLimit = %d, want %d", e.key, got.QuotaLimit, wantLimit[e.key])
		}
		if got.Unit != "count" {
			t.Errorf("details[%s].Unit = %q, want count", e.key, got.Unit)
		}
		if got.Used < 0 {
			t.Errorf("details[%s].Used = %d, want >= 0", e.key, got.Used)
		}
	}

	// Repeatable quota_key filtering.
	filtered, err := c.ListQuotaDetails(&elb.ListQuotaDetailsRequest{
		QuotaKey: &[]string{"certificate", "loadbalancer"},
	})
	if err != nil || filtered.Quotas == nil || len(*filtered.Quotas) != 2 {
		t.Fatalf("ListQuotaDetails(filtered) = %+v, %v", filtered, err)
	}

	certUsed := func() int32 {
		t.Helper()
		res, err := c.ListQuotaDetails(&elb.ListQuotaDetailsRequest{QuotaKey: &[]string{"certificate"}})
		if err != nil || res.Quotas == nil || len(*res.Quotas) != 1 || (*res.Quotas)[0].QuotaKey != "certificate" {
			t.Fatalf("ListQuotaDetails(certificate) = %+v, %v", res, err)
		}
		return (*res.Quotas)[0].Used
	}

	beforeCert := certUsed()
	certPEM, keyPEM := elbGenerateCertPEM(t, "quota-test.example.com", false)
	created, err := c.CreateCertificate(&elb.CreateCertificateRequest{Body: &elb.CreateCertificateRequestBody{
		Certificate: &elb.CreateCertificateOption{
			Name:        ptr("sdk-quota-cert"),
			Certificate: ptr(certPEM),
			PrivateKey:  ptr(keyPEM),
		},
	}})
	if err != nil || created.Certificate == nil {
		t.Fatalf("CreateCertificate: %+v, %v", created, err)
	}
	certID := created.Certificate.Id
	certDeleted := false
	t.Cleanup(func() {
		if certDeleted {
			return
		}
		_, _ = c.DeleteCertificate(&elb.DeleteCertificateRequest{CertificateId: certID})
	})

	if got := certUsed(); got != beforeCert+1 {
		t.Fatalf("certificate used after create = %d, want %d", got, beforeCert+1)
	}
	if _, err := c.DeleteCertificate(&elb.DeleteCertificateRequest{CertificateId: certID}); err != nil {
		t.Fatalf("DeleteCertificate: %v", err)
	}
	certDeleted = true
	if got := certUsed(); got != beforeCert {
		t.Fatalf("certificate used after delete = %d, want %d", got, beforeCert)
	}
}

// TestQuotaEVS exercises EVS v2 CinderListQuotas and verifies that volume
// count and gigabytes usage track volume creation and deletion.
func TestQuotaEVS(t *testing.T) {
	c := newEVS(t)

	getQuotas := func() *evs.QuotaList {
		t.Helper()
		res, err := c.CinderListQuotas(&evs.CinderListQuotasRequest{
			TargetProjectId: projectID,
			Usage:           evs.GetCinderListQuotasRequestUsageEnum().TRUE,
		})
		if err != nil || res.QuotaSet == nil {
			t.Fatalf("CinderListQuotas: %+v, %v", res, err)
		}
		return res.QuotaSet
	}

	before := getQuotas()
	if before.Id != projectID {
		t.Errorf("QuotaSet.Id = %q, want %q", before.Id, projectID)
	}
	if before.Volumes == nil || before.Gigabytes == nil || before.Snapshots == nil {
		t.Fatalf("QuotaSet missing core quota entries: %+v", before)
	}
	if before.Volumes.Reserved != 0 || before.Gigabytes.Reserved != 0 || before.Snapshots.Reserved != 0 {
		t.Errorf("expected reserved == 0, got volumes=%d gigabytes=%d snapshots=%d",
			before.Volumes.Reserved, before.Gigabytes.Reserved, before.Snapshots.Reserved)
	}
	if before.Volumes.Limit != -1 && before.Volumes.Limit <= 0 {
		t.Errorf("Volumes.Limit = %d, want -1 or > 0", before.Volumes.Limit)
	}
	if before.Gigabytes.Limit <= 0 && before.Gigabytes.Limit != -1 {
		t.Errorf("Gigabytes.Limit = %d, want > 0 or -1", before.Gigabytes.Limit)
	}
	if before.Snapshots.Limit <= 0 && before.Snapshots.Limit != -1 {
		t.Errorf("Snapshots.Limit = %d, want > 0 or -1", before.Snapshots.Limit)
	}

	azRes, err := c.CinderListAvailabilityZones(&evs.CinderListAvailabilityZonesRequest{})
	if err != nil || azRes.AvailabilityZoneInfo == nil || len(*azRes.AvailabilityZoneInfo) == 0 {
		t.Fatalf("CinderListAvailabilityZones: %+v, %v", azRes, err)
	}
	az := (*azRes.AvailabilityZoneInfo)[0].ZoneName

	const volSize int32 = 15
	cr, err := c.CreateVolume(&evs.CreateVolumeRequest{
		Body: &evs.CreateVolumeRequestBody{
			Volume: &evs.CreateVolumeOption{
				AvailabilityZone: az,
				Name:             ptr("sdk-quota-vol"),
				Size:             volSize,
				VolumeType:       evs.GetCreateVolumeOptionVolumeTypeEnum().SSD,
			},
		},
	})
	if err != nil || cr.JobId == nil || cr.VolumeIds == nil || len(*cr.VolumeIds) != 1 {
		t.Fatalf("CreateVolume: %+v, %v", cr, err)
	}
	volID := (*cr.VolumeIds)[0]
	volDeleted := false
	t.Cleanup(func() {
		if volDeleted {
			return
		}
		if del, err := c.DeleteVolume(&evs.DeleteVolumeRequest{VolumeId: volID}); err == nil && del.JobId != nil {
			waitEVSJob(t, c, *del.JobId)
		}
	})
	waitEVSJob(t, c, *cr.JobId)

	afterCreate := getQuotas()
	if afterCreate.Volumes.InUse != before.Volumes.InUse+1 {
		t.Fatalf("Volumes.InUse after create = %d, want %d", afterCreate.Volumes.InUse, before.Volumes.InUse+1)
	}
	if afterCreate.Gigabytes.InUse != before.Gigabytes.InUse+volSize {
		t.Fatalf("Gigabytes.InUse after create = %d, want %d", afterCreate.Gigabytes.InUse, before.Gigabytes.InUse+volSize)
	}
	if before.VolumesSSD != nil && afterCreate.VolumesSSD != nil {
		if afterCreate.VolumesSSD.Limit != -1 || afterCreate.VolumesSSD.InUse != before.VolumesSSD.InUse+1 {
			t.Errorf("VolumesSSD = %+v, want limit=-1 in_use=%d", afterCreate.VolumesSSD, before.VolumesSSD.InUse+1)
		}
	}
	if before.GigabytesSSD != nil && afterCreate.GigabytesSSD != nil {
		if afterCreate.GigabytesSSD.Limit != -1 || afterCreate.GigabytesSSD.InUse != before.GigabytesSSD.InUse+volSize {
			t.Errorf("GigabytesSSD = %+v, want limit=-1 in_use=%d", afterCreate.GigabytesSSD, before.GigabytesSSD.InUse+volSize)
		}
	}

	del, err := c.DeleteVolume(&evs.DeleteVolumeRequest{VolumeId: volID})
	if err != nil || del.JobId == nil {
		t.Fatalf("DeleteVolume: %+v, %v", del, err)
	}
	waitEVSJob(t, c, *del.JobId)
	volDeleted = true

	afterDelete := getQuotas()
	if afterDelete.Volumes.InUse != before.Volumes.InUse {
		t.Fatalf("Volumes.InUse after delete = %d, want %d", afterDelete.Volumes.InUse, before.Volumes.InUse)
	}
	if afterDelete.Gigabytes.InUse != before.Gigabytes.InUse {
		t.Fatalf("Gigabytes.InUse after delete = %d, want %d", afterDelete.Gigabytes.InUse, before.Gigabytes.InUse)
	}
}

// TestQuotaECSAndIMS exercises ECS v2 ShowServerLimits and IMS v2
// ShowImageQuota, tracking server creation/deletion (instances, cores,
// RAM) and private image creation/deletion.
func TestQuotaECSAndIMS(t *testing.T) {
	net2 := newV2(t, realEndpoint)
	net3 := newV3(t)
	compute := newECS(t)
	images := newIMS(t)

	getLimits := func() *ecs.ServerLimits {
		t.Helper()
		res, err := compute.ShowServerLimits(&ecs.ShowServerLimitsRequest{})
		if err != nil || res.Absolute == nil {
			t.Fatalf("ShowServerLimits: %+v, %v", res, err)
		}
		return res.Absolute
	}
	getImageQuota := func() ims.QuotaInfo {
		t.Helper()
		res, err := images.ShowImageQuota(&ims.ShowImageQuotaRequest{})
		if err != nil || res.Quotas == nil || len(res.Quotas.Resources) != 1 {
			t.Fatalf("ShowImageQuota: %+v, %v", res, err)
		}
		return res.Quotas.Resources[0]
	}

	beforeECS := getLimits()
	if beforeECS.MaxTotalInstances <= 0 && beforeECS.MaxTotalInstances != -1 {
		t.Errorf("MaxTotalInstances = %d, want > 0 or -1", beforeECS.MaxTotalInstances)
	}
	if beforeECS.MaxTotalCores <= 0 && beforeECS.MaxTotalCores != -1 {
		t.Errorf("MaxTotalCores = %d, want > 0 or -1", beforeECS.MaxTotalCores)
	}
	if beforeECS.MaxTotalFloatingIps <= 0 && beforeECS.MaxTotalFloatingIps != -1 {
		t.Errorf("MaxTotalFloatingIps = %d, want > 0 or -1", beforeECS.MaxTotalFloatingIps)
	}
	if beforeECS.MaxSecurityGroups <= 0 && beforeECS.MaxSecurityGroups != -1 {
		t.Errorf("MaxSecurityGroups = %d, want > 0 or -1", beforeECS.MaxSecurityGroups)
	}
	if beforeECS.MaxTotalRAMSize != -1 {
		t.Errorf("MaxTotalRAMSize = %d, want -1", beforeECS.MaxTotalRAMSize)
	}
	if beforeECS.MaxTotalKeypairs != -1 {
		t.Errorf("MaxTotalKeypairs = %d, want -1", beforeECS.MaxTotalKeypairs)
	}
	if beforeECS.MaxServerMeta != 128 || beforeECS.MaxPersonality != 5 || beforeECS.MaxPersonalitySize != 10240 ||
		beforeECS.MaxImageMeta != 128 || beforeECS.MaxSecurityGroupRules != 20 || beforeECS.MaxServerGroups != 10 ||
		beforeECS.MaxServerGroupMembers != 16 || beforeECS.TotalServerGroupsUsed != 0 {
		t.Errorf("unexpected static ECS limits: %+v", beforeECS)
	}

	beforeIMS := getImageQuota()
	if beforeIMS.Type != "image" || beforeIMS.Min != 1 || beforeIMS.Max != 1000 || beforeIMS.Used < 0 {
		t.Fatalf("ShowImageQuota = %+v", beforeIMS)
	}
	if beforeIMS.Quota <= 0 && beforeIMS.Quota != -1 {
		t.Errorf("ShowImageQuota.Quota = %d, want > 0 or -1", beforeIMS.Quota)
	}

	// Build minimal network + server + private image, with full cleanup.
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{
		Name: ptr("sdk-quota-ecs-vpc"), Cidr: ptr("10.96.0.0/16"),
	}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID := vc.Vpc.Id
	t.Cleanup(func() {
		eventually(t, "quota ECS VPC to be deletable", func() bool {
			_, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID})
			return err == nil
		})
	})
	eventually(t, "quota ECS VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})

	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: "sdk-quota-ecs-subnet", Cidr: "10.96.1.0/24", GatewayIp: "10.96.1.1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID := sc.Subnet.Id
	t.Cleanup(func() {
		eventually(t, "quota ECS subnet to be deletable", func() bool {
			_, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
			return err == nil
		})
	})
	eventually(t, "quota ECS subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})

	gc, err := net3.CreateSecurityGroup(&v3.CreateSecurityGroupRequest{Body: &v3.CreateSecurityGroupRequestBody{
		SecurityGroup: &v3.CreateSecurityGroupOption{Name: "sdk-quota-ecs-sg"},
	}})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	sgID := gc.SecurityGroup.Id
	t.Cleanup(func() {
		_, _ = net3.DeleteSecurityGroup(&v3.DeleteSecurityGroupRequest{SecurityGroupId: sgID})
	})

	listed, err := images.ListImages(&ims.ListImagesRequest{Name: ptr("Ubuntu 22.04 server 64bit")})
	if err != nil || listed.Images == nil || len(*listed.Images) != 1 {
		t.Fatalf("ListImages(Ubuntu): %+v, %v", listed, err)
	}
	publicImage := (*listed.Images)[0].Id

	// s6.large.2 has 2 vCPUs and 4096 MiB RAM.
	srvRes, err := compute.CreatePostPaidServers(&ecs.CreatePostPaidServersRequest{Body: &ecs.CreatePostPaidServersRequestBody{
		Server: &ecs.PostPaidServer{
			Name:           "sdk-quota-srv",
			ImageRef:       publicImage,
			FlavorRef:      "s6.large.2",
			Vpcid:          vpcID,
			Nics:           []ecs.PostPaidServerNic{{SubnetId: &subnetID}},
			RootVolume:     &ecs.PostPaidServerRootVolume{Volumetype: ecs.GetPostPaidServerRootVolumeVolumetypeEnum().GPSSD},
			SecurityGroups: &[]ecs.PostPaidServerSecurityGroup{{Id: &sgID}},
		},
	}})
	if err != nil || srvRes.JobId == nil || srvRes.ServerIds == nil || len(*srvRes.ServerIds) != 1 {
		t.Fatalf("CreatePostPaidServers: %+v, %v", srvRes, err)
	}
	serverID := (*srvRes.ServerIds)[0]
	waitECSJob := func(jobID string) {
		t.Helper()
		var last *ecs.ShowJobResponse
		eventually(t, "ECS job "+jobID+" to finish", func() bool {
			job, err := compute.ShowJob(&ecs.ShowJobRequest{JobId: jobID})
			if err != nil {
				t.Fatalf("ShowJob: %v", err)
			}
			last = job
			return job.Status != nil && job.Status.Value() != "RUNNING" && job.Status.Value() != "INIT"
		})
		if last.Status.Value() != "SUCCESS" {
			t.Fatalf("ECS job %s ended %s: %v", jobID, last.Status.Value(), last.FailReason)
		}
	}
	srvDeleted := false
	t.Cleanup(func() {
		if srvDeleted {
			return
		}
		if del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
			Servers: []ecs.ServerId{{Id: serverID}},
		}}); err == nil && del.JobId != nil {
			waitECSJob(*del.JobId)
		}
	})
	waitECSJob(*srvRes.JobId)

	afterServer := getLimits()
	if afterServer.TotalInstancesUsed != beforeECS.TotalInstancesUsed+1 {
		t.Fatalf("TotalInstancesUsed = %d, want %d", afterServer.TotalInstancesUsed, beforeECS.TotalInstancesUsed+1)
	}
	if afterServer.TotalCoresUsed != beforeECS.TotalCoresUsed+2 {
		t.Fatalf("TotalCoresUsed = %d, want %d", afterServer.TotalCoresUsed, beforeECS.TotalCoresUsed+2)
	}
	if afterServer.TotalRAMUsed != beforeECS.TotalRAMUsed+4096 {
		t.Fatalf("TotalRAMUsed = %d, want %d", afterServer.TotalRAMUsed, beforeECS.TotalRAMUsed+4096)
	}
	if afterServer.TotalSecurityGroupsUsed != beforeECS.TotalSecurityGroupsUsed+1 {
		t.Errorf("TotalSecurityGroupsUsed = %d, want %d", afterServer.TotalSecurityGroupsUsed, beforeECS.TotalSecurityGroupsUsed+1)
	}

	// Private image from the server increments/decrements IMS image quota usage.
	ic, err := images.CreateImage(&ims.CreateImageRequest{Body: &ims.CreateImageRequestBody{
		Name: ptr("sdk-quota-img"), InstanceId: &serverID,
	}})
	if err != nil || ic.JobId == nil {
		t.Fatalf("CreateImage: %+v, %v", ic, err)
	}
	var imageID string
	eventually(t, "IMS job to succeed", func() bool {
		ij, err := images.ShowJob(&ims.ShowJobRequest{JobId: *ic.JobId})
		if err != nil {
			t.Fatalf("IMS ShowJob: %v", err)
		}
		if ij.Entities != nil && ij.Entities.ImageId != nil {
			imageID = *ij.Entities.ImageId
		}
		return ij.Status != nil && ij.Status.Value() == "SUCCESS"
	})
	imgDeleted := false
	t.Cleanup(func() {
		if imgDeleted || imageID == "" {
			return
		}
		_, _ = images.GlanceDeleteImage(&ims.GlanceDeleteImageRequest{ImageId: imageID})
	})

	afterImgCreate := getImageQuota()
	if afterImgCreate.Used != beforeIMS.Used+1 {
		t.Fatalf("IMS image used after create = %d, want %d", afterImgCreate.Used, beforeIMS.Used+1)
	}
	if _, err := images.GlanceDeleteImage(&ims.GlanceDeleteImageRequest{ImageId: imageID}); err != nil {
		t.Fatalf("GlanceDeleteImage: %v", err)
	}
	imgDeleted = true

	afterImgDelete := getImageQuota()
	if afterImgDelete.Used != beforeIMS.Used {
		t.Fatalf("IMS image used after delete = %d, want %d", afterImgDelete.Used, beforeIMS.Used)
	}

	// Delete the server and verify ECS limits return to baseline.
	del, err := compute.DeleteServers(&ecs.DeleteServersRequest{Body: &ecs.DeleteServersRequestBody{
		Servers: []ecs.ServerId{{Id: serverID}},
	}})
	if err != nil || del.JobId == nil {
		t.Fatalf("DeleteServers: %+v, %v", del, err)
	}
	waitECSJob(*del.JobId)
	srvDeleted = true

	afterServerDelete := getLimits()
	if afterServerDelete.TotalInstancesUsed != beforeECS.TotalInstancesUsed ||
		afterServerDelete.TotalCoresUsed != beforeECS.TotalCoresUsed ||
		afterServerDelete.TotalRAMUsed != beforeECS.TotalRAMUsed {
		t.Fatalf("ECS limits after server delete = instances:%d cores:%d ram:%d, want %d/%d/%d",
			afterServerDelete.TotalInstancesUsed, afterServerDelete.TotalCoresUsed, afterServerDelete.TotalRAMUsed,
			beforeECS.TotalInstancesUsed, beforeECS.TotalCoresUsed, beforeECS.TotalRAMUsed)
	}
}

// TestQuotaRDS exercises RDS v3 ShowQuotas.
func TestQuotaRDS(t *testing.T) {
	c := newRDS(t)

	res, err := c.ShowQuotas(&rds.ShowQuotasRequest{})
	if err != nil || res.Quotas == nil || res.Quotas.Resources == nil || len(*res.Quotas.Resources) != 1 {
		t.Fatalf("rds/v3 ShowQuotas: %+v, %v", res, err)
	}
	r := (*res.Quotas.Resources)[0]
	if r.Type == nil || *r.Type != "instance" {
		t.Errorf("RDS quota type = %v, want instance", r.Type)
	}
	if r.Quota == nil || (*r.Quota <= 0 && *r.Quota != -1) {
		t.Errorf("RDS quota = %v, want > 0 or -1", r.Quota)
	}
	if r.Used == nil || *r.Used < 0 {
		t.Errorf("RDS used = %v, want >= 0", r.Used)
	}
}

// TestQuotaIAM exercises IAM v3 ShowProjectQuota and ShowDomainQuota,
// verifying bounds and tracking group creation/deletion.
func TestQuotaIAM(t *testing.T) {
	c, c5 := iamClients(t, "AKIAMQUOTAS000000000")

	domains, err := c.KeystoneListAuthDomains(&iam.KeystoneListAuthDomainsRequest{})
	if err != nil || domains.Domains == nil || len(*domains.Domains) == 0 {
		t.Fatalf("KeystoneListAuthDomains: %+v, %v", domains, err)
	}
	domainID := (*domains.Domains)[0].Id

	// Project quota.
	projRes, err := c.ShowProjectQuota(&iam.ShowProjectQuotaRequest{ProjectId: projectID})
	if err != nil || projRes.Quotas == nil || projRes.Quotas.Resources == nil || len(*projRes.Quotas.Resources) != 1 {
		t.Fatalf("ShowProjectQuota: %+v, %v", projRes, err)
	}
	pr := (*projRes.Quotas.Resources)[0]
	if pr.Type == nil || *pr.Type != "project" {
		t.Errorf("ShowProjectQuota type = %v, want project", pr.Type)
	}
	if pr.Min == nil || *pr.Min != 0 || pr.Max == nil || *pr.Max != 50 {
		t.Errorf("ShowProjectQuota min/max = %v/%v, want 0/50", pr.Min, pr.Max)
	}
	if pr.Quota == nil || *pr.Quota <= 0 {
		t.Errorf("ShowProjectQuota quota = %v, want > 0", pr.Quota)
	}
	if pr.Used == nil || *pr.Used < 1 {
		t.Errorf("ShowProjectQuota used = %v, want >= 1", pr.Used)
	}

	// Domain quota: user, group, agency.
	getDomainQuotas := func() map[string]iam.Resources {
		t.Helper()
		res, err := c.ShowDomainQuota(&iam.ShowDomainQuotaRequest{DomainId: domainID})
		if err != nil || res.Quotas == nil || res.Quotas.Resources == nil {
			t.Fatalf("ShowDomainQuota: %+v, %v", res, err)
		}
		out := make(map[string]iam.Resources, len(*res.Quotas.Resources))
		for _, r := range *res.Quotas.Resources {
			if r.Type != nil {
				out[*r.Type] = r
			}
		}
		return out
	}

	before := getDomainQuotas()
	for _, tc := range []struct {
		typ string
		min int32
		max int32
	}{
		{"user", 50, 1000},
		{"group", 10, 300},
		{"agency", 10, 300},
	} {
		r, ok := before[tc.typ]
		if !ok {
			t.Fatalf("ShowDomainQuota missing %q: %+v", tc.typ, before)
		}
		if r.Min == nil || *r.Min != tc.min || r.Max == nil || *r.Max != tc.max {
			t.Errorf("ShowDomainQuota[%s] min/max = %v/%v, want %d/%d", tc.typ, r.Min, r.Max, tc.min, tc.max)
		}
		if r.Quota == nil || (*r.Quota <= 0 && *r.Quota != -1) {
			t.Errorf("ShowDomainQuota[%s] quota = %v, want > 0 or -1", tc.typ, r.Quota)
		}
		if r.Used == nil || *r.Used < 0 {
			t.Errorf("ShowDomainQuota[%s] used = %v, want >= 0", tc.typ, r.Used)
		}
	}

	// Creating and deleting a group increments and decrements group.used.
	beforeGroups := *before["group"].Used
	g, err := c5.CreateGroupV5(&v5.CreateGroupV5Request{Body: &v5.CreateGroupReqBody{GroupName: "sdk-quota-group"}})
	if err != nil || g.Group == nil {
		t.Fatalf("CreateGroupV5: %+v, %v", g, err)
	}
	groupID := g.Group.GroupId
	groupDeleted := false
	t.Cleanup(func() {
		if groupDeleted {
			return
		}
		_, _ = c5.DeleteGroupV5(&v5.DeleteGroupV5Request{GroupId: groupID})
	})

	afterCreate := getDomainQuotas()
	if *afterCreate["group"].Used != beforeGroups+1 {
		t.Fatalf("group used after create = %d, want %d", *afterCreate["group"].Used, beforeGroups+1)
	}
	if _, err := c5.DeleteGroupV5(&v5.DeleteGroupV5Request{GroupId: groupID}); err != nil {
		t.Fatalf("DeleteGroupV5: %v", err)
	}
	groupDeleted = true

	afterDelete := getDomainQuotas()
	if *afterDelete["group"].Used != beforeGroups {
		t.Fatalf("group used after delete = %d, want %d", *afterDelete["group"].Used, beforeGroups)
	}
}
