package quota

import (
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	t.Parallel()
	var l Limits
	for k, want := range map[Key]int{VPCVPC: 150, EVSVolumes: Unlimited, ELBLoadBalancer: 50, ECSInstances: 20, VPCPublicIP: 50} {
		if got := l.Get(k); got != want {
			t.Errorf("%s = %d, want %d", k, got, want)
		}
	}
	for _, k := range Keys() {
		if v, src, ok := Default(k); !ok || src == "" || v < Unlimited {
			t.Errorf("%s: default %d, source %q, ok %v", k, v, src, ok)
		}
	}
}

func TestAllows(t *testing.T) {
	t.Parallel()
	l := For(map[Key]int{VPCVPC: 2, EVSVolumes: Unlimited, ELBPool: 0})
	for _, tc := range []struct {
		k          Key
		used, want int
		ok         bool
	}{
		{VPCVPC, 0, 1, true},
		{VPCVPC, 1, 1, true},
		{VPCVPC, 2, 1, false},
		{VPCVPC, 0, 3, false}, // a batch that would cross the limit
		{VPCVPC, 5, 0, true},  // over the limit already, adding nothing
		{EVSVolumes, 1 << 30, 1, true},
		{ELBPool, 0, 1, false},
	} {
		if got := l.Allows(tc.k, tc.used, tc.want); got != tc.ok {
			t.Errorf("Allows(%s, %d, %d) = %v, want %v", tc.k, tc.used, tc.want, got, tc.ok)
		}
	}
}

func TestWithLeavesTheOriginal(t *testing.T) {
	t.Parallel()
	a := For(map[Key]int{VPCVPC: 3})
	b := a.With(VPCVPC, 7)
	if a.Get(VPCVPC) != 3 || b.Get(VPCVPC) != 7 {
		t.Fatalf("a %d, b %d", a.Get(VPCVPC), b.Get(VPCVPC))
	}
}

func TestUnknownKeyPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("Get of an unknown key did not panic")
		}
	}()
	Limits{}.Get("vpc.typo")
}

func TestParse(t *testing.T) {
	t.Parallel()
	reserved := map[Key]string{ECSInstances: "-ecs-max-servers"}
	l, err := Parse(Limits{}, " vpc.vpc=500, elb.loadbalancer=-1,,evs.snapshots=0 ", reserved)
	if err != nil {
		t.Fatal(err)
	}
	if l.Get(VPCVPC) != 500 || l.Get(ELBLoadBalancer) != Unlimited || l.Get(EVSSnapshots) != 0 || l.Get(VPCSubnet) != 400 {
		t.Errorf("parsed %v", l.set)
	}
	if l, err := Parse(Limits{}, "", nil); err != nil || len(l.set) != 0 {
		t.Errorf("empty spec: %v, %v", l.set, err)
	}
	for spec, want := range map[string]string{
		"vpc.typo=1":          "unknown quota",
		"vpc.vpc":             "key=value",
		"vpc.vpc=-2":          "-1 for unlimited",
		"vpc.vpc=many":        "-1 for unlimited",
		"vpc.vpc=1,vpc.vpc=2": "twice",
		"ecs.instances=5":     "-ecs-max-servers",
	} {
		if _, err := Parse(Limits{}, spec, reserved); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error with %q", spec, err, want)
		}
	}
}
