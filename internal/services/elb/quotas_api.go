package elb

import (
	"net/http"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/quota"
)

// quotaWire mirrors SDK elb/v3 model Quota.
type quotaWire struct {
	ProjectID                            string `json:"project_id"`
	Loadbalancer                         int    `json:"loadbalancer"`
	Certificate                          int    `json:"certificate"`
	Listener                             int    `json:"listener"`
	L7Policy                             int    `json:"l7policy"`
	ConditionPerPolicy                   int    `json:"condition_per_policy"`
	Pool                                 int    `json:"pool"`
	Healthmonitor                        int    `json:"healthmonitor"`
	Member                               int    `json:"member"`
	MembersPerPool                       int    `json:"members_per_pool"`
	ListenersPerPool                     int    `json:"listeners_per_pool"`
	IPGroup                              int    `json:"ipgroup"`
	IPGroupBindings                      int    `json:"ipgroup_bindings"`
	IPGroupMaxLength                     int    `json:"ipgroup_max_length"`
	IPGroupsPerListener                  int    `json:"ipgroups_per_listener"`
	SecurityPolicy                       int    `json:"security_policy"`
	ListenersPerLoadbalancer             int    `json:"listeners_per_loadbalancer"`
	PoolsPerL7Policy                     int    `json:"pools_per_l7policy"`
	L7PoliciesPerListener                int    `json:"l7policies_per_listener"`
	FreeInstanceMembersPerPool           int    `json:"free_instance_members_per_pool"`
	FreeInstanceListenersPerLoadbalancer int    `json:"free_instance_listeners_per_loadbalancer"`
}

// showQuotaResponse mirrors SDK elb/v3 model ShowQuotaResponse.
type showQuotaResponse struct {
	RequestID string    `json:"request_id"`
	Quota     quotaWire `json:"quota"`
}

// quotaInfoWire mirrors SDK elb/v3 model QuotaInfo.
type quotaInfoWire struct {
	QuotaKey   string `json:"quota_key"`
	QuotaLimit int    `json:"quota_limit"`
	Used       int    `json:"used"`
	Unit       string `json:"unit"`
}

// listQuotaDetailsResponse mirrors SDK elb/v3 model ListQuotaDetailsResponse.
type listQuotaDetailsResponse struct {
	RequestID string          `json:"request_id"`
	Quotas    []quotaInfoWire `json:"quotas"`
}

func (s *Service) handleShowQuota(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return httpx.WriteJSON(w, http.StatusOK, showQuotaResponse{
		RequestID: requestID(r),
		Quota: quotaWire{
			ProjectID:                            t.ProjectID,
			Loadbalancer:                         s.quotas.Get(quota.ELBLoadBalancer),
			Certificate:                          s.quotas.Get(quota.ELBCertificate),
			Listener:                             s.quotas.Get(quota.ELBListener),
			L7Policy:                             s.quotas.Get(quota.ELBL7Policy),
			ConditionPerPolicy:                   quota.Unlimited,
			Pool:                                 s.quotas.Get(quota.ELBPool),
			Healthmonitor:                        quota.Unlimited,
			Member:                               s.quotas.Get(quota.ELBMember),
			MembersPerPool:                       quota.Unlimited,
			ListenersPerPool:                     quota.Unlimited,
			IPGroup:                              quota.Unlimited,
			IPGroupBindings:                      quota.Unlimited,
			IPGroupMaxLength:                     quota.Unlimited,
			IPGroupsPerListener:                  quota.Unlimited,
			SecurityPolicy:                       quota.Unlimited,
			ListenersPerLoadbalancer:             quota.Unlimited,
			PoolsPerL7Policy:                     quota.Unlimited,
			L7PoliciesPerListener:                s.quotas.Get(quota.ELBL7PoliciesPerListener),
			FreeInstanceMembersPerPool:           quota.Unlimited,
			FreeInstanceListenersPerLoadbalancer: quota.Unlimited,
		},
	})
}

func (s *Service) handleListQuotaDetails(w http.ResponseWriter, r *http.Request, t Tenant) error {
	ctx := r.Context()
	keys := r.URL.Query()["quota_key"]

	var (
		pols       []l7Policy
		polsLoaded bool
	)
	loadPolicies := func() ([]l7Policy, error) {
		if !polsLoaded {
			var err error
			pols, err = s.l7Policies(t).List(ctx, nil)
			if err != nil {
				return nil, err
			}
			polsLoaded = true
		}
		return pols, nil
	}

	items := make([]quotaInfoWire, 0, 7)

	if matchesAny(keys, "loadbalancer") {
		lbs, err := s.loadBalancers(t).List(ctx, nil)
		if err != nil {
			return err
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "loadbalancer",
			QuotaLimit: s.quotas.Get(quota.ELBLoadBalancer),
			Used:       len(lbs),
			Unit:       "count",
		})
	}
	if matchesAny(keys, "listener") {
		lsns, err := s.listeners(t).List(ctx, nil)
		if err != nil {
			return err
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "listener",
			QuotaLimit: s.quotas.Get(quota.ELBListener),
			Used:       len(lsns),
			Unit:       "count",
		})
	}
	if matchesAny(keys, "l7policy") {
		all, err := loadPolicies()
		if err != nil {
			return err
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "l7policy",
			QuotaLimit: s.quotas.Get(quota.ELBL7Policy),
			Used:       len(all),
			Unit:       "count",
		})
	}
	if matchesAny(keys, "pool") {
		pools, err := s.pools(t).List(ctx, nil)
		if err != nil {
			return err
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "pool",
			QuotaLimit: s.quotas.Get(quota.ELBPool),
			Used:       len(pools),
			Unit:       "count",
		})
	}
	if matchesAny(keys, "member") {
		mems, err := s.members(t).List(ctx, nil)
		if err != nil {
			return err
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "member",
			QuotaLimit: s.quotas.Get(quota.ELBMember),
			Used:       len(mems),
			Unit:       "count",
		})
	}
	if matchesAny(keys, "certificate") {
		certs, err := s.certificates(t).List(ctx, nil)
		if err != nil {
			return err
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "certificate",
			QuotaLimit: s.quotas.Get(quota.ELBCertificate),
			Used:       len(certs),
			Unit:       "count",
		})
	}
	if matchesAny(keys, "l7policies_per_listener") {
		all, err := loadPolicies()
		if err != nil {
			return err
		}
		perListener := make(map[string]int)
		maxPerListener := 0
		for _, p := range all {
			perListener[p.ListenerID]++
			if perListener[p.ListenerID] > maxPerListener {
				maxPerListener = perListener[p.ListenerID]
			}
		}
		items = append(items, quotaInfoWire{
			QuotaKey:   "l7policies_per_listener",
			QuotaLimit: s.quotas.Get(quota.ELBL7PoliciesPerListener),
			Used:       maxPerListener,
			Unit:       "count",
		})
	}

	return httpx.WriteJSON(w, http.StatusOK, listQuotaDetailsResponse{
		RequestID: requestID(r),
		Quotas:    items,
	})
}
