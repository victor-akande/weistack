package elb

import "net/http"

// Wave 0 stubs for PR 2 (certificates, L7 policies/rules, IP groups, security policies, tags).

func (s *Service) handleCreateCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateCertificate")(w, r, t)
}

func (s *Service) handleListCertificates(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListCertificates")(w, r, t)
}

func (s *Service) handleShowCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowCertificate")(w, r, t)
}

func (s *Service) handleUpdateCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateCertificate")(w, r, t)
}

func (s *Service) handleDeleteCertificate(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteCertificate")(w, r, t)
}

func (s *Service) handleCreateL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateL7Policy")(w, r, t)
}

func (s *Service) handleListL7Policies(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListL7Policies")(w, r, t)
}

func (s *Service) handleShowL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowL7Policy")(w, r, t)
}

func (s *Service) handleUpdateL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateL7Policy")(w, r, t)
}

func (s *Service) handleDeleteL7Policy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteL7Policy")(w, r, t)
}

func (s *Service) handleCreateL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateL7Rule")(w, r, t)
}

func (s *Service) handleListL7Rules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListL7Rules")(w, r, t)
}

func (s *Service) handleShowL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowL7Rule")(w, r, t)
}

func (s *Service) handleUpdateL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateL7Rule")(w, r, t)
}

func (s *Service) handleDeleteL7Rule(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteL7Rule")(w, r, t)
}

func (s *Service) handleListAllL7Rules(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListAllL7Rules")(w, r, t)
}

func (s *Service) handleCreateIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateIpGroup")(w, r, t)
}

func (s *Service) handleListIPGroups(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListIpGroups")(w, r, t)
}

func (s *Service) handleShowIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowIpGroup")(w, r, t)
}

func (s *Service) handleUpdateIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateIpGroup")(w, r, t)
}

func (s *Service) handleDeleteIPGroup(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteIpGroup")(w, r, t)
}

func (s *Service) handleCreateSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateSecurityPolicy")(w, r, t)
}

func (s *Service) handleListSecurityPolicies(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListSecurityPolicies")(w, r, t)
}

func (s *Service) handleShowSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowSecurityPolicy")(w, r, t)
}

func (s *Service) handleUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateSecurityPolicy")(w, r, t)
}

func (s *Service) handleDeleteSecurityPolicy(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteSecurityPolicy")(w, r, t)
}

func (s *Service) handleListSystemSecurityPolicies(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListSystemSecurityPolicies")(w, r, t)
}

func (s *Service) handleShowLoadBalancerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowLoadbalancerTags")(w, r, t)
}

func (s *Service) handleChangeLoadBalancerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ChangeLoadbalancerTags")(w, r, t)
}

func (s *Service) handleListLoadBalancerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListLoadbalancerTags")(w, r, t)
}

func (s *Service) handleCreateLoadBalancerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateLoadbalancerTag")(w, r, t)
}

func (s *Service) handleDeleteLoadBalancerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteLoadbalancerTag")(w, r, t)
}

func (s *Service) handleListLoadBalancersByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListLoadbalancersByTags")(w, r, t)
}

func (s *Service) handleShowListenerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowListenerTags")(w, r, t)
}

func (s *Service) handleChangeListenerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ChangeListenerTags")(w, r, t)
}

func (s *Service) handleListListenerTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListListenerTags")(w, r, t)
}

func (s *Service) handleCreateListenerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateListenerTag")(w, r, t)
}

func (s *Service) handleDeleteListenerTag(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteListenerTag")(w, r, t)
}

func (s *Service) handleListListenersByTags(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListListenersByTags")(w, r, t)
}
