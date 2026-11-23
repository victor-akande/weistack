package quota

import "testing"

// FuzzParse: no -quotas setting crashes Parse, and what it accepts is
// within range.
func FuzzParse(f *testing.F) {
	f.Add("vpc.vpc=500,elb.loadbalancer=-1")
	f.Add(",,=,vpc.vpc==1")
	f.Fuzz(func(t *testing.T, spec string) {
		l, err := Parse(Limits{}, spec, map[Key]string{ECSInstances: "-ecs-max-servers"})
		if err != nil {
			return
		}
		for _, k := range Keys() {
			if v := l.Get(k); v < Unlimited {
				t.Fatalf("%s = %d from %q", k, v, spec)
			}
		}
	})
}
