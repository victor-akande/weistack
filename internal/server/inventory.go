package server

import (
	"net/http"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/httpx"
	"github.com/victor-akande/weistack/internal/core/inventory"
)

// newInventory joins the enabled services that report resources.
func (s *Server) newInventory() *inventory.Inventory {
	var reporters []inventory.Reporter
	for _, name := range s.names {
		if rep, ok := s.services[name].svc.(inventory.Reporter); ok {
			reporters = append(reporters, rep)
		}
	}
	o := inventory.Options{Reporters: reporters}
	if s.accounts != nil {
		o.Owner = s.accounts.ProjectOwner
	}
	return inventory.New(o)
}

// inventoryResponse is GET /_weistack/inventory. A resource and its
// relationships have the fields of Huawei Cloud's Config (RMS), plus
// account_id; the relationships are those from the resource.
type inventoryResponse struct {
	Resources []inventoryResource `json:"resources"`
	Count     int                 `json:"count"`
}

type inventoryResource struct {
	ID                string              `json:"id"`
	Name              string              `json:"name"`
	Provider          string              `json:"provider"`
	Type              string              `json:"type"`
	AccountID         string              `json:"account_id"`
	RegionID          string              `json:"region_id"`
	ProjectID         string              `json:"project_id"`
	EpID              string              `json:"ep_id"`
	Created           string              `json:"created,omitempty"`
	Updated           string              `json:"updated,omitempty"`
	ProvisioningState string              `json:"provisioning_state"`
	Tags              map[string]string   `json:"tags"`
	Relations         []inventoryRelation `json:"relations"`
}

type inventoryRelation struct {
	RelationType     string `json:"relation_type"`
	FromResourceType string `json:"from_resource_type"`
	ToResourceType   string `json:"to_resource_type"`
	FromResourceID   string `json:"from_resource_id"`
	ToResourceID     string `json:"to_resource_id"`
}

// rmsTime is how Config writes times: UTC, to the second.
func rmsTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// handleInventory is GET /_weistack/inventory: every resource of the
// enabled services, selected by the query parameters type
// ("provider.type", as Config's), account_id, region_id, project_id,
// ep_id and id.
func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	f := inventory.Filter{
		AccountID:           q.Get("account_id"),
		RegionID:            q.Get("region_id"),
		ProjectID:           q.Get("project_id"),
		EnterpriseProjectID: q.Get("ep_id"),
		ID:                  q.Get("id"),
	}
	if t := q.Get("type"); t != "" {
		typ, ok := inventory.ParseType(t)
		if !ok {
			return apierr.New(http.StatusBadRequest, "WeiStack.0400", "unknown resource type %q", t).
				WithHint("give a type as provider.type, such as ecs.cloudservers; docs/inventory.md lists them")
		}
		f.Type = typ
	}
	snap, err := s.inventory.Collect(r.Context())
	if err != nil {
		return apierr.Internal(err)
	}
	selected := snap.Select(f)
	out := inventoryResponse{Resources: make([]inventoryResource, 0, len(selected)), Count: len(selected)}
	for _, res := range selected {
		v := inventoryResource{
			ID: res.ID, Name: res.Name, Provider: res.Type.Provider, Type: res.Type.Name,
			AccountID: res.AccountID, RegionID: res.RegionID, ProjectID: res.ProjectID,
			EpID: res.EnterpriseProjectID, Created: rmsTime(res.Created), Updated: rmsTime(res.Updated),
			ProvisioningState: string(res.State), Tags: res.Tags,
			Relations: make([]inventoryRelation, 0, len(res.Relations)),
		}
		for _, ref := range res.Relations {
			v.Relations = append(v.Relations, inventoryRelation{
				RelationType:     string(ref.Relation),
				FromResourceType: res.Type.String(), ToResourceType: ref.Type.String(),
				FromResourceID: res.ID, ToResourceID: ref.ID,
			})
		}
		out.Resources = append(out.Resources, v)
	}
	return httpx.WriteJSON(w, http.StatusOK, out)
}
