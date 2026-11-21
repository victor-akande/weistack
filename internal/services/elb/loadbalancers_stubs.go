package elb

import "net/http"

// Wave 0 stubs for W1 (load balancers, flavors, availability zones). W1 removes this file.

func (s *Service) handleCreateLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("CreateLoadBalancer")(w, r, t)
}

func (s *Service) handleListLoadBalancers(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListLoadBalancers")(w, r, t)
}

func (s *Service) handleShowLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowLoadBalancer")(w, r, t)
}

func (s *Service) handleUpdateLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("UpdateLoadBalancer")(w, r, t)
}

func (s *Service) handleDeleteLoadBalancer(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteLoadBalancer")(w, r, t)
}

func (s *Service) handleDeleteLoadBalancerForce(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("DeleteLoadBalancerForce")(w, r, t)
}

func (s *Service) handleShowLoadBalancerStatus(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowLoadBalancerStatus")(w, r, t)
}

func (s *Service) handleBatchAddAvailableZones(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("BatchAddAvailableZones")(w, r, t)
}

func (s *Service) handleBatchRemoveAvailableZones(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("BatchRemoveAvailableZones")(w, r, t)
}

func (s *Service) handleListFlavors(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListFlavors")(w, r, t)
}

func (s *Service) handleShowFlavor(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ShowFlavor")(w, r, t)
}

func (s *Service) handleListAvailabilityZones(w http.ResponseWriter, r *http.Request, t Tenant) error {
	return s.notImplemented("ListAvailabilityZones")(w, r, t)
}
