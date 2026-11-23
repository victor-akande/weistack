// Command smoke checks that the web app's stack is healthy, with
// read-only credentials, and exits non-zero if it is not: every web server
// ACTIVE and ONLINE behind the load balancer, the NAT gateway ACTIVE and
// the database ACTIVE. It uses Huawei's Go SDK, through WeiStack's -lan
// proxy, with Huawei Cloud's real endpoints.
//
//	. ./use.sh operator
//	go run ./smoke -project ... -pool ... -nat ... -db ... -servers 2
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	elb "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	elbmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/model"
	nat "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2"
	natmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nat/v2/model"
	rds "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3"
	rdsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/rds/v3/model"
)

func main() {
	project := flag.String("project", "", "the region's project ID")
	pool := flag.String("pool", "", "the web pool's ID")
	natID := flag.String("nat", "", "the NAT gateway's ID")
	db := flag.String("db", "", "the RDS instance's ID")
	servers := flag.Int("servers", 2, "how many web servers there should be")
	flag.Parse()
	if *project == "" || *pool == "" || *natID == "" || *db == "" {
		flag.Usage()
		os.Exit(2)
	}
	region := env("HW_REGION_NAME", "ap-southeast-1")
	c, err := newClients(region, *project)
	if err != nil {
		fmt.Fprintln(os.Stderr, "smoke:", err)
		os.Exit(2)
	}

	failed := 0
	check := func(what string, ok bool, detail string) {
		mark := "ok  "
		if !ok {
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %-28s %s\n", mark, what, detail)
	}

	list, err := c.ecs.ListServersDetails(&ecsmodel.ListServersDetailsRequest{})
	check("web servers", err == nil && list.Servers != nil && countActive(*list.Servers) == *servers,
		fmt.Sprintf("%d ACTIVE, want %d %v", countActive(deref(list, err)), *servers, errText(err)))

	members, err := c.elb.ListMembers(&elbmodel.ListMembersRequest{PoolId: *pool})
	online := 0
	if err == nil && members.Members != nil {
		for _, m := range *members.Members {
			if m.OperatingStatus == "ONLINE" {
				online++
			}
		}
	}
	check("load balancer members", err == nil && online == *servers, fmt.Sprintf("%d ONLINE, want %d %v", online, *servers, errText(err)))

	gw, err := c.nat.ShowNatGateway(&natmodel.ShowNatGatewayRequest{NatGatewayId: *natID})
	natStatus := ""
	if err == nil && gw.NatGateway != nil {
		natStatus = gw.NatGateway.Status.Value()
	}
	check("NAT gateway", natStatus == "ACTIVE", natStatus+" "+errText(err))

	dbs, err := c.rds.ListInstances(&rdsmodel.ListInstancesRequest{Id: db})
	dbStatus := ""
	if err == nil && dbs.Instances != nil && len(*dbs.Instances) == 1 {
		dbStatus = (*dbs.Instances)[0].Status
	}
	check("database", dbStatus == "ACTIVE", dbStatus+" "+errText(err))

	if failed > 0 {
		fmt.Printf("%d check(s) failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("the stack is healthy")
}

type clients struct {
	ecs *ecs.EcsClient
	elb *elb.ElbClient
	nat *nat.NatClient
	rds *rds.RdsClient
}

// newClients builds one client per service. The Go SDK does not read
// HTTPS_PROXY, so the proxy (WEISTACK, the -lan address) is set here; the
// system's CAs, which hold WeiStack's after step 2, verify it.
func newClients(region, project string) (*clients, error) {
	proxy, err := url.Parse(os.Getenv("WEISTACK"))
	if err != nil || proxy.Host == "" {
		return nil, fmt.Errorf("set WEISTACK to the cloud machine, for example https://192.168.1.20:8781")
	}
	port, _ := strconv.Atoi(proxy.Port())
	hc := config.DefaultHttpConfig().
		WithProxy(config.NewProxy().WithSchema(proxy.Scheme).WithHost(proxy.Hostname()).WithPort(port))
	cred, err := basic.NewCredentialsBuilder().
		WithAk(os.Getenv("HW_ACCESS_KEY")).
		WithSk(os.Getenv("HW_SECRET_KEY")).
		WithProjectId(project).
		SafeBuild()
	if err != nil {
		return nil, err
	}
	build := func(b *core.HcHttpClientBuilder, service string) (*core.HcHttpClient, error) {
		return b.WithEndpoints([]string{"https://" + service + "." + region + ".myhuaweicloud.com"}).
			WithCredential(cred).WithHttpConfig(hc).SafeBuild()
	}
	var c clients
	if h, err := build(ecs.EcsClientBuilder(), "ecs"); err == nil {
		c.ecs = ecs.NewEcsClient(h)
	} else {
		return nil, err
	}
	if h, err := build(elb.ElbClientBuilder(), "elb"); err == nil {
		c.elb = elb.NewElbClient(h)
	} else {
		return nil, err
	}
	if h, err := build(nat.NatClientBuilder(), "nat"); err == nil {
		c.nat = nat.NewNatClient(h)
	} else {
		return nil, err
	}
	if h, err := build(rds.RdsClientBuilder(), "rds"); err == nil {
		c.rds = rds.NewRdsClient(h)
	} else {
		return nil, err
	}
	return &c, nil
}

func countActive(servers []ecsmodel.ServerDetail) int {
	n := 0
	for _, s := range servers {
		if s.Status == "ACTIVE" {
			n++
		}
	}
	return n
}

func deref(list *ecsmodel.ListServersDetailsResponse, err error) []ecsmodel.ServerDetail {
	if err != nil || list == nil || list.Servers == nil {
		return nil
	}
	return *list.Servers
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return "(" + err.Error() + ")"
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
