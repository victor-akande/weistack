package sdk

import (
	"testing"

	rdsv3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3/model"
	v2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
	v3 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v3/model"
)

func newRDS(t *testing.T) *rdsv3.RdsClient {
	t.Helper()
	return newRDSAt(t, emulatorAddr)
}

func newRDSAt(t *testing.T, addr string) *rdsv3.RdsClient {
	t.Helper()
	hc, err := rdsv3.RdsClientBuilder().
		WithEndpoints([]string{"http://rds." + region + ".myhuaweicloud.com"}).
		WithCredential(credentials(t)).
		WithHttpConfig(httpConfigAt(addr)).
		SafeBuild()
	if err != nil {
		t.Fatalf("building RDS client: %v", err)
	}
	return rdsv3.NewRdsClient(hc)
}

// dbNetwork creates the VPC, subnet and security group a database lives
// in, and returns their IDs and a function that deletes them.
func dbNetwork(t *testing.T, name, cidr string) (vpcID, subnetID, groupID string, teardown func()) {
	t.Helper()
	net2, net3 := newV2(t, realEndpoint), newV3(t)
	vc, err := net2.CreateVpc(&v2.CreateVpcRequest{Body: &v2.CreateVpcRequestBody{Vpc: &v2.CreateVpcOption{Name: ptr(name), Cidr: ptr("10.30.0.0/16")}}})
	if err != nil {
		t.Fatalf("CreateVpc: %v", err)
	}
	vpcID = vc.Vpc.Id
	eventually(t, "the VPC to become OK", func() bool {
		s, err := net2.ShowVpc(&v2.ShowVpcRequest{VpcId: vpcID})
		return err == nil && s.Vpc.Status.Value() == "OK"
	})
	sc, err := net2.CreateSubnet(&v2.CreateSubnetRequest{Body: &v2.CreateSubnetRequestBody{Subnet: &v2.CreateSubnetOption{
		Name: name, Cidr: cidr, GatewayIp: cidr[:len(cidr)-4] + "1", VpcId: vpcID,
	}}})
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	subnetID = sc.Subnet.Id
	eventually(t, "the subnet to become ACTIVE", func() bool {
		s, err := net2.ShowSubnet(&v2.ShowSubnetRequest{SubnetId: subnetID})
		return err == nil && s.Subnet.Status.Value() == "ACTIVE"
	})
	gc, err := net3.CreateSecurityGroup(&v3.CreateSecurityGroupRequest{Body: &v3.CreateSecurityGroupRequestBody{
		SecurityGroup: &v3.CreateSecurityGroupOption{Name: name},
	}})
	if err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	groupID = gc.SecurityGroup.Id
	return vpcID, subnetID, groupID, func() {
		t.Helper()
		if _, err := net3.DeleteSecurityGroup(&v3.DeleteSecurityGroupRequest{SecurityGroupId: groupID}); err != nil {
			t.Errorf("DeleteSecurityGroup: %v", err)
		}
		if _, err := net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID}); err != nil {
			t.Errorf("DeleteSubnet: %v", err)
		}
		if _, err := net2.DeleteVpc(&v2.DeleteVpcRequest{VpcId: vpcID}); err != nil {
			t.Errorf("DeleteVpc: %v", err)
		}
	}
}

// waitRDSJob waits for an RDS job to finish and requires it to succeed.
func waitRDSJob(t *testing.T, c *rdsv3.RdsClient, what, jobID string) {
	t.Helper()
	eventually(t, what+" to finish", func() bool {
		res, err := c.ListJobInfo(&rds.ListJobInfoRequest{Id: jobID})
		if err != nil {
			t.Fatalf("ListJobInfo: %v", err)
		}
		switch res.Job.Status.Value() {
		case "Failed":
			t.Fatalf("%s failed: %v", what, res.Job.FailReason)
		case "Completed":
			return true
		}
		return false
	})
}

// TestRDSInstances creates, finds and deletes MySQL and PostgreSQL
// instances through the official SDK, inside a network made with the
// VPC SDK.
func TestRDSInstances(t *testing.T) {
	c := newRDS(t)
	vpcID, subnetID, groupID, teardown := dbNetwork(t, "rds-sdk", "10.30.1.0/24")

	// Discover what can be created.
	stores, err := c.ListDatastores(&rds.ListDatastoresRequest{DatabaseName: rds.GetListDatastoresRequestDatabaseNameEnum().MY_SQL})
	if err != nil || stores.DataStores == nil || len(*stores.DataStores) != 2 || (*stores.DataStores)[1].Name != "8.0" {
		t.Fatalf("ListDatastores = %+v, %v", stores, err)
	}
	flavors, err := c.ListFlavors(&rds.ListFlavorsRequest{
		DatabaseName: rds.GetListFlavorsRequestDatabaseNameEnum().POSTGRE_SQL, VersionName: ptr("16"),
	})
	if err != nil || flavors.Flavors == nil || len(*flavors.Flavors) != 12 {
		t.Fatalf("ListFlavors = %+v, %v", flavors, err)
	}
	var haSpec string
	for _, f := range *flavors.Flavors {
		if f.InstanceMode == "ha" && f.Vcpus == "2" && f.Ram == 4 {
			haSpec = f.SpecCode
		}
	}
	if haSpec != "rds.pg.n1.large.2.ha" {
		t.Fatalf("no 2 vCPU / 4 GB HA PostgreSQL flavor (found %q)", haSpec)
	}

	create := func(body rds.InstanceRequest) (string, string) {
		t.Helper()
		res, err := c.CreateInstance(&rds.CreateInstanceRequest{Body: &body})
		if err != nil {
			t.Fatalf("CreateInstance(%s): %v", body.Name, err)
		}
		if res.HttpStatusCode != 202 || res.Instance == nil || res.Instance.Id == nil || res.JobId == nil ||
			res.Instance.Status == nil || *res.Instance.Status != "BUILD" {
			t.Fatalf("CreateInstance(%s) = %+v", body.Name, res)
		}
		return *res.Instance.Id, *res.JobId
	}
	base := func(name string) rds.InstanceRequest {
		return rds.InstanceRequest{
			Name: name, Region: region, VpcId: vpcID, SubnetId: subnetID, SecurityGroupId: groupID,
			Password: ptr("Weistack@2026"),
		}
	}

	mysql := base("sdk-mysql")
	mysql.Datastore = &rds.Datastore{Type: rds.GetDatastoreTypeEnum().MY_SQL, Version: "8.0"}
	mysql.FlavorRef = "rds.mysql.n1.large.2"
	mysql.Volume = &rds.Volume{Type: rds.GetVolumeTypeEnum().CLOUDSSD, Size: 40}
	mysql.AvailabilityZone = region + "a"
	mysql.BackupStrategy = &rds.BackupStrategy{StartTime: "08:15-09:15", KeepDays: ptr(int32(3))}
	mysql.Tags = &[]rds.TagWithKeyValue{{Key: "app", Value: "shop"}}
	mysqlID, mysqlJob := create(mysql)

	pg := base("sdk-pg")
	pg.Datastore = &rds.Datastore{Type: rds.GetDatastoreTypeEnum().POSTGRE_SQL, Version: "16"}
	pg.FlavorRef = haSpec
	pg.Ha = &rds.Ha{Mode: rds.GetHaModeEnum().HA, ReplicationMode: rds.GetHaReplicationModeEnum().SYNC}
	pg.Volume = &rds.Volume{Type: rds.GetVolumeTypeEnum().ESSD, Size: 100}
	pg.AvailabilityZone = region + "a," + region + "b"
	pgID, pgJob := create(pg)

	waitRDSJob(t, c, "the MySQL creation", mysqlJob)
	waitRDSJob(t, c, "the PostgreSQL creation", pgJob)

	// Find them the way the API intends: list with a filter.
	list, err := c.ListInstances(&rds.ListInstancesRequest{Id: &mysqlID})
	if err != nil || list.TotalCount == nil || *list.TotalCount != 1 {
		t.Fatalf("ListInstances(id) = %+v, %v", list, err)
	}
	m := (*list.Instances)[0]
	if m.Status != "ACTIVE" || m.Port != 3306 || m.Type != "Single" || len(m.PrivateIps) != 1 || m.Datastore.Version != "8.0" ||
		m.BackupStrategy.KeepDays != 3 || m.Volume.Size != 40 || len(m.Nodes) != 1 || m.DbUserName != "root" ||
		len(m.Tags) != 1 || m.Tags[0].Value != "shop" {
		t.Errorf("MySQL instance = %+v", m)
	}
	pgType := rds.GetListInstancesRequestDatastoreTypeEnum().POSTGRE_SQL
	list, err = c.ListInstances(&rds.ListInstancesRequest{DatastoreType: &pgType})
	if err != nil || len(*list.Instances) != 1 {
		t.Fatalf("ListInstances(PostgreSQL) = %+v, %v", list, err)
	}
	p := (*list.Instances)[0]
	if p.Id != pgID || p.Type != "Ha" || p.Port != 5432 || p.Ha == nil || p.Ha.ReplicationMode.Value() != "sync" || len(p.Nodes) != 2 {
		t.Errorf("PostgreSQL instance = %+v", p)
	}
	if m.PrivateIps[0] == p.PrivateIps[0] {
		t.Errorf("two instances share the address %s", m.PrivateIps[0])
	}

	// Errors as the SDK decodes them.
	dup := base("sdk-mysql")
	dup.Datastore, dup.FlavorRef, dup.Volume, dup.AvailabilityZone = mysql.Datastore, mysql.FlavorRef, mysql.Volume, mysql.AvailabilityZone
	_, err = c.CreateInstance(&rds.CreateInstanceRequest{Body: &dup})
	wantError(t, err, 409, "DBS.200022")
	weak := base("sdk-weak")
	weak.Datastore, weak.FlavorRef, weak.Volume, weak.AvailabilityZone = mysql.Datastore, mysql.FlavorRef, mysql.Volume, mysql.AvailabilityZone
	weak.Password = ptr("password")
	_, err = c.CreateInstance(&rds.CreateInstanceRequest{Body: &weak})
	wantError(t, err, 400, "DBS.200052")
	elsewhere := base("sdk-elsewhere")
	elsewhere.Datastore, elsewhere.FlavorRef, elsewhere.Volume, elsewhere.AvailabilityZone = mysql.Datastore, mysql.FlavorRef, mysql.Volume, mysql.AvailabilityZone
	elsewhere.SubnetId = unknownID
	_, err = c.CreateInstance(&rds.CreateInstanceRequest{Body: &elsewhere})
	wantError(t, err, 404, "DBS.200501")
	_, err = c.DeleteInstance(&rds.DeleteInstanceRequest{InstanceId: "00000000000000000000000000000000in01"})
	wantError(t, err, 404, "DBS.200002")

	// Teardown. The subnet cannot go while a database holds an address.
	net2 := newV2(t, realEndpoint)
	_, err = net2.DeleteSubnet(&v2.DeleteSubnetRequest{VpcId: vpcID, SubnetId: subnetID})
	wantError(t, err, 500, "VPC.0208")
	for _, id := range []string{mysqlID, pgID} {
		res, err := c.DeleteInstance(&rds.DeleteInstanceRequest{InstanceId: id})
		if err != nil || res.JobId == nil {
			t.Fatalf("DeleteInstance: %+v, %v", res, err)
		}
		waitRDSJob(t, c, "the deletion", *res.JobId)
	}
	if left, err := c.ListInstances(&rds.ListInstancesRequest{}); err != nil || *left.TotalCount != 0 {
		t.Fatalf("instances left after deletion: %+v, %v", left, err)
	}
	teardown()
}

// TestRDSScenario is end-to-end scenario 4 of the plan through the
// official SDK: create a MySQL instance in a subnet, wait for ACTIVE,
// resize it, scale its storage, reboot it, back it up, and delete it.
func TestRDSScenario(t *testing.T) {
	c := newRDS(t)
	vpcID, subnetID, groupID, teardown := dbNetwork(t, "rds-scenario", "10.30.2.0/24")

	body := rds.InstanceRequest{
		Name: "scenario-mysql", Region: region, VpcId: vpcID, SubnetId: subnetID, SecurityGroupId: groupID,
		Datastore:        &rds.Datastore{Type: rds.GetDatastoreTypeEnum().MY_SQL, Version: "8.0"},
		FlavorRef:        "rds.mysql.n1.large.2",
		Volume:           &rds.Volume{Type: rds.GetVolumeTypeEnum().CLOUDSSD, Size: 40},
		AvailabilityZone: region + "a",
		Password:         ptr("Weistack@2026"),
	}
	created, err := c.CreateInstance(&rds.CreateInstanceRequest{Body: &body})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	id := *created.Instance.Id
	waitRDSJob(t, c, "the creation", *created.JobId)

	show := func() rds.InstanceResponse {
		t.Helper()
		res, err := c.ListInstances(&rds.ListInstancesRequest{Id: &id})
		if err != nil || res.Instances == nil || len(*res.Instances) != 1 {
			t.Fatalf("ListInstances(id) = %+v, %v", res, err)
		}
		return (*res.Instances)[0]
	}
	if got := show(); got.Status != "ACTIVE" {
		t.Fatalf("after creation: %s", got.Status)
	}

	// Resize.
	resized, err := c.StartResizeFlavorAction(&rds.StartResizeFlavorActionRequest{InstanceId: id, Body: &rds.ResizeFlavorRequest{
		ResizeFlavor: &rds.ResizeFlavorObject{SpecCode: "rds.mysql.n1.xlarge.4"},
	}})
	if err != nil || resized.JobId == nil {
		t.Fatalf("StartResizeFlavorAction: %+v, %v", resized, err)
	}
	if got := show(); got.Status != "MODIFYING" {
		t.Errorf("during resize: %s", got.Status)
	}
	waitRDSJob(t, c, "the resize", *resized.JobId)
	if got := show(); got.FlavorRef != "rds.mysql.n1.xlarge.4" || got.Cpu == nil || *got.Cpu != "4" || got.Status != "ACTIVE" {
		t.Errorf("after resize: %s, %v vCPUs, %s", got.FlavorRef, got.Cpu, got.Status)
	}

	// Storage.
	grown, err := c.StartInstanceEnlargeVolumeAction(&rds.StartInstanceEnlargeVolumeActionRequest{InstanceId: id, Body: &rds.EnlargeVolumeRequestBody{
		EnlargeVolume: &rds.EnlargeVolumeObject{Size: 100},
	}})
	if err != nil || grown.JobId == nil {
		t.Fatalf("StartInstanceEnlargeVolumeAction: %+v, %v", grown, err)
	}
	waitRDSJob(t, c, "the storage scaling", *grown.JobId)
	if got := show(); got.Volume.Size != 100 {
		t.Errorf("storage after scaling: %d GB", got.Volume.Size)
	}
	_, err = c.StartInstanceEnlargeVolumeAction(&rds.StartInstanceEnlargeVolumeActionRequest{InstanceId: id, Body: &rds.EnlargeVolumeRequestBody{
		EnlargeVolume: &rds.EnlargeVolumeObject{Size: 60},
	}})
	wantError(t, err, 400, "DBS.200306")

	// Reboot.
	rebooted, err := c.StartInstanceRestartAction(&rds.StartInstanceRestartActionRequest{InstanceId: id, Body: &rds.InstanceRestartRequsetBody{
		Restart: &rds.RestartConfiguration{},
	}})
	if err != nil || rebooted.JobId == nil {
		t.Fatalf("StartInstanceRestartAction: %+v, %v", rebooted, err)
	}
	if got := show(); got.Status != "REBOOTING" {
		t.Errorf("during reboot: %s", got.Status)
	}
	// Nothing else can start meanwhile.
	_, err = c.StartInstanceRestartAction(&rds.StartInstanceRestartActionRequest{InstanceId: id, Body: &rds.InstanceRestartRequsetBody{Restart: &rds.RestartConfiguration{}}})
	wantError(t, err, 409, "DBS.200011")
	waitRDSJob(t, c, "the reboot", *rebooted.JobId)

	// Backup.
	backup, err := c.CreateManualBackup(&rds.CreateManualBackupRequest{Body: &rds.CreateManualBackupRequestBody{
		InstanceId: id, Name: "scenario-backup", Description: ptr("taken by the SDK suite"),
	}})
	if err != nil || backup.Backup == nil || backup.Backup.Status.Value() != "BUILDING" {
		t.Fatalf("CreateManualBackup = %+v, %v", backup, err)
	}
	backupID := backup.Backup.Id
	eventually(t, "the backup to complete", func() bool {
		res, err := c.ListBackups(&rds.ListBackupsRequest{InstanceId: id, BackupId: &backupID})
		if err != nil {
			t.Fatalf("ListBackups: %v", err)
		}
		return len(*res.Backups) == 1 && (*res.Backups)[0].Status.Value() == "COMPLETED"
	})
	if got := show(); got.Status != "ACTIVE" {
		t.Errorf("after the backup: %s", got.Status)
	}

	// Delete. The manual backup is kept, as in the real service.
	del, err := c.DeleteInstance(&rds.DeleteInstanceRequest{InstanceId: id})
	if err != nil || del.JobId == nil {
		t.Fatalf("DeleteInstance: %+v, %v", del, err)
	}
	waitRDSJob(t, c, "the deletion", *del.JobId)
	kept, err := c.ListBackups(&rds.ListBackupsRequest{InstanceId: id})
	if err != nil || kept.TotalCount == nil || *kept.TotalCount != 1 {
		t.Fatalf("backups after deleting the instance = %+v, %v", kept, err)
	}
	if _, err := c.DeleteManualBackup(&rds.DeleteManualBackupRequest{BackupId: backupID}); err != nil {
		t.Fatalf("DeleteManualBackup: %v", err)
	}
	_, err = c.DeleteManualBackup(&rds.DeleteManualBackupRequest{BackupId: backupID})
	wantError(t, err, 404, "DBS.201010")
	teardown()
}
