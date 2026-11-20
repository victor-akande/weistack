package nat

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/reqctx"
)

type createPrivateNatRequest struct {
	Gateway *createPrivateNatOption `json:"gateway"`
}

type downlinkVPCOption struct {
	VirsubnetID     string  `json:"virsubnet_id"`
	NgportIPAddress *string `json:"ngport_ip_address"`
}

type createPrivateNatOption struct {
	Name                string              `json:"name"`
	Description         *string             `json:"description"`
	Spec                *string             `json:"spec"`
	DownlinkVPCs        []downlinkVPCOption `json:"downlink_vpcs"`
	Tags                *[]tag              `json:"tags"`
	EnterpriseProjectID *string             `json:"enterprise_project_id"`
}

type updatePrivateNatRequest struct {
	Gateway *updatePrivateNatOption `json:"gateway"`
}

type updatePrivateNatOption struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Spec        *string `json:"spec"`
}

type downlinkVPCResp struct {
	VPCID           string `json:"vpc_id"`
	VirsubnetID     string `json:"virsubnet_id"`
	NgportIPAddress string `json:"ngport_ip_address"`
}

type privateNatResponseBody struct {
	ID                   string            `json:"id"`
	ProjectID            string            `json:"project_id"`
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	Spec                 string            `json:"spec"`
	Status               string            `json:"status"`
	CreatedAt            string            `json:"created_at"`
	UpdatedAt            string            `json:"updated_at"`
	DownlinkVPCs         []downlinkVPCResp `json:"downlink_vpcs"`
	Tags                 []tag             `json:"tags"`
	EnterpriseProjectID  string            `json:"enterprise_project_id"`
	RuleMax              int               `json:"rule_max"`
	TransitIPPoolSizeMax int               `json:"transit_ip_pool_size_max"`
}

type privateNatEnvelope struct {
	Gateway   privateNatResponseBody `json:"gateway"`
	RequestID string                 `json:"request_id"`
}

type listPrivateNatsResponse struct {
	Gateways  []privateNatResponseBody `json:"gateways"`
	RequestID string                   `json:"request_id"`
	PageInfo  pageInfo                 `json:"page_info"`
}

type listSpecsResponse struct {
	Specs     []privateSpec `json:"specs"`
	RequestID string        `json:"request_id"`
}

type createTransitSubnetRequest struct {
	TransitSubnet *createTransitSubnetOption `json:"transit_subnet"`
}

type createTransitSubnetOption struct {
	Name               string  `json:"name"`
	Description        *string `json:"description"`
	VirsubnetID        string  `json:"virsubnet_id"`
	VirsubnetProjectID string  `json:"virsubnet_project_id"`
	Tags               *[]tag  `json:"tags"`
}

type updateTransitSubnetRequest struct {
	TransitSubnet *updateTransitSubnetOption `json:"transit_subnet"`
}

type updateTransitSubnetOption struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type transitSubnetResponseBody struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	VirsubnetProjectID string `json:"virsubnet_project_id"`
	ProjectID          string `json:"project_id"`
	VPCID              string `json:"vpc_id"`
	VirsubnetID        string `json:"virsubnet_id"`
	CIDR               string `json:"cidr"`
	Type               string `json:"type"`
	Status             string `json:"status"`
	IPCount            int    `json:"ip_count"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	Tags               []tag  `json:"tags"`
}

type transitSubnetEnvelope struct {
	TransitSubnet transitSubnetResponseBody `json:"transit_subnet"`
	RequestID     string                    `json:"request_id"`
}

type listTransitSubnetsResponse struct {
	TransitSubnets []transitSubnetResponseBody `json:"transit_subnets"`
	RequestID      string                      `json:"request_id"`
	PageInfo       pageInfo                    `json:"page_info"`
}

func privateGWRequestID(r *http.Request) string {
	return reqctx.From(r.Context()).RequestID
}

func clonePrivateTagsOrEmpty(tags []tag) []tag {
	if len(tags) == 0 {
		return []tag{}
	}
	return slices.Clone(tags)
}

func toPrivateGatewayResp(t Tenant, g privateGateway) privateNatResponseBody {
	spec, _ := lookupPrivateSpec(g.Spec)
	return privateNatResponseBody{
		ID:          g.ID,
		ProjectID:   t.ProjectID,
		Name:        g.Name,
		Description: g.Description,
		Spec:        g.Spec,
		Status:      StatusActive,
		CreatedAt:   g.CreatedAt.UTC().Format(privateTimeFormat),
		UpdatedAt:   g.UpdatedAt.UTC().Format(privateTimeFormat),
		DownlinkVPCs: []downlinkVPCResp{{
			VPCID:           g.VPCID,
			VirsubnetID:     g.SubnetID,
			NgportIPAddress: g.NgportIP,
		}},
		Tags:                 clonePrivateTagsOrEmpty(g.Tags),
		EnterpriseProjectID:  g.EnterpriseProjectID,
		RuleMax:              spec.RuleMax,
		TransitIPPoolSizeMax: privateTransitIPPoolSizeMax,
	}
}

func toTransitSubnetResp(t Tenant, ts transitSubnet, ipCount int) transitSubnetResponseBody {
	return transitSubnetResponseBody{
		ID:                 ts.ID,
		Name:               ts.Name,
		Description:        ts.Description,
		VirsubnetProjectID: t.ProjectID,
		ProjectID:          t.ProjectID,
		VPCID:              ts.VPCID,
		VirsubnetID:        ts.SubnetID,
		CIDR:               ts.CIDR,
		Type:               "VPC",
		Status:             StatusActive,
		IPCount:            ipCount,
		CreatedAt:          ts.CreatedAt.UTC().Format(privateTimeFormat),
		UpdatedAt:          ts.UpdatedAt.UTC().Format(privateTimeFormat),
		Tags:               clonePrivateTagsOrEmpty(ts.Tags),
	}
}

func (s *Service) handleCreatePrivateNat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createPrivateNatRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Gateway == nil {
		return errBadJSON("gateway is required")
	}
	opt := req.Gateway
	downlinks := make([]downlinkVPCInput, len(opt.DownlinkVPCs))
	for i, dl := range opt.DownlinkVPCs {
		downlinks[i] = downlinkVPCInput{
			VirsubnetID:     dl.VirsubnetID,
			NgportIPAddress: derefString(dl.NgportIPAddress),
		}
	}
	var tags []tag
	if opt.Tags != nil {
		tags = *opt.Tags
	}
	g, err := s.createPrivateGateway(r.Context(), t, createPrivateGatewayInput{
		Name:                opt.Name,
		Description:         derefString(opt.Description),
		Spec:                opt.Spec,
		DownlinkVPCs:        downlinks,
		Tags:                tags,
		EnterpriseProjectID: derefString(opt.EnterpriseProjectID),
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, privateNatEnvelope{
		Gateway:   toPrivateGatewayResp(t, g),
		RequestID: privateGWRequestID(r),
	})
}

func (s *Service) handleListPrivateNats(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errBadJSON("%s", err)
	}
	items, info, err := s.listPrivateGateways(r.Context(), t, listPrivateGatewaysFilter{
		IDs:                  nonEmpty(q["id"]),
		ProjectIDs:           nonEmpty(q["project_id"]),
		Names:                nonEmpty(q["name"]),
		Descriptions:         nonEmpty(q["description"]),
		Specs:                nonEmpty(q["spec"]),
		Statuses:             nonEmpty(q["status"]),
		VPCIDs:               nonEmpty(q["vpc_id"]),
		VirsubnetIDs:         nonEmpty(q["virsubnet_id"]),
		EnterpriseProjectIDs: nonEmpty(q["enterprise_project_id"]),
		Page:                 page,
	})
	if err != nil {
		return err
	}
	out := make([]privateNatResponseBody, 0, len(items))
	for _, g := range items {
		out = append(out, toPrivateGatewayResp(t, g))
	}
	return httpx.WriteJSON(w, http.StatusOK, listPrivateNatsResponse{
		Gateways:  out,
		RequestID: privateGWRequestID(r),
		PageInfo:  info,
	})
}

func (s *Service) handleShowPrivateNat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "gateway_id")
	g, err := s.getPrivateGateway(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, privateNatEnvelope{
		Gateway:   toPrivateGatewayResp(t, g),
		RequestID: privateGWRequestID(r),
	})
}

func (s *Service) handleUpdatePrivateNat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updatePrivateNatRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Gateway == nil {
		return errBadJSON("gateway is required")
	}
	id := chi.URLParam(r, "gateway_id")
	opt := req.Gateway
	g, err := s.updatePrivateGateway(r.Context(), t, id, updatePrivateGatewayInput{
		Name:        opt.Name,
		Description: opt.Description,
		Spec:        opt.Spec,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, privateNatEnvelope{
		Gateway:   toPrivateGatewayResp(t, g),
		RequestID: privateGWRequestID(r),
	})
}

func (s *Service) handleDeletePrivateNat(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "gateway_id")
	if err := s.deletePrivateGateway(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) handleListSpecs(w http.ResponseWriter, r *http.Request, _ Tenant) error {
	return httpx.WriteJSON(w, http.StatusOK, listSpecsResponse{
		Specs:     slices.Clone(privateSpecs),
		RequestID: privateGWRequestID(r),
	})
}

func (s *Service) handleCreateTransitSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req createTransitSubnetRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.TransitSubnet == nil {
		return errBadJSON("transit_subnet is required")
	}
	opt := req.TransitSubnet
	var tags []tag
	if opt.Tags != nil {
		tags = *opt.Tags
	}
	ts, ipCount, err := s.createTransitSubnet(r.Context(), t, createTransitSubnetInput{
		Name:               opt.Name,
		Description:        derefString(opt.Description),
		VirsubnetID:        opt.VirsubnetID,
		VirsubnetProjectID: opt.VirsubnetProjectID,
		Tags:               tags,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusCreated, transitSubnetEnvelope{
		TransitSubnet: toTransitSubnetResp(t, ts, ipCount),
		RequestID:     privateGWRequestID(r),
	})
}

func (s *Service) handleListTransitSubnets(w http.ResponseWriter, r *http.Request, t Tenant) error {
	q := r.URL.Query()
	page, err := pagination.ParseMarker(q, listLimits)
	if err != nil {
		return errBadJSON("%s", err)
	}
	items, counts, info, err := s.listTransitSubnets(r.Context(), t, listTransitSubnetsFilter{
		IDs:                 nonEmpty(q["id"]),
		Names:               nonEmpty(q["name"]),
		Descriptions:        nonEmpty(q["description"]),
		VirsubnetProjectIDs: nonEmpty(q["virsubnet_project_id"]),
		VPCIDs:              nonEmpty(q["vpc_id"]),
		VirsubnetIDs:        nonEmpty(q["virsubnet_id"]),
		Statuses:            nonEmpty(q["status"]),
		Page:                page,
	})
	if err != nil {
		return err
	}
	out := make([]transitSubnetResponseBody, 0, len(items))
	for _, ts := range items {
		out = append(out, toTransitSubnetResp(t, ts, counts[ts.SubnetID]))
	}
	return httpx.WriteJSON(w, http.StatusOK, listTransitSubnetsResponse{
		TransitSubnets: out,
		RequestID:      privateGWRequestID(r),
		PageInfo:       info,
	})
}

func (s *Service) handleShowTransitSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "transit_subnet_id")
	ts, ipCount, err := s.getTransitSubnet(r.Context(), t, id)
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, transitSubnetEnvelope{
		TransitSubnet: toTransitSubnetResp(t, ts, ipCount),
		RequestID:     privateGWRequestID(r),
	})
}

func (s *Service) handleUpdateTransitSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	var req updateTransitSubnetRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.TransitSubnet == nil {
		return errBadJSON("transit_subnet is required")
	}
	id := chi.URLParam(r, "transit_subnet_id")
	opt := req.TransitSubnet
	ts, ipCount, err := s.updateTransitSubnet(r.Context(), t, id, updateTransitSubnetInput{
		Name:        opt.Name,
		Description: opt.Description,
	})
	if err != nil {
		return err
	}
	return httpx.WriteJSON(w, http.StatusOK, transitSubnetEnvelope{
		TransitSubnet: toTransitSubnetResp(t, ts, ipCount),
		RequestID:     privateGWRequestID(r),
	})
}

func (s *Service) handleDeleteTransitSubnet(w http.ResponseWriter, r *http.Request, t Tenant) error {
	id := chi.URLParam(r, "transit_subnet_id")
	if err := s.deleteTransitSubnet(r.Context(), t, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
