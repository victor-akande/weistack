// Package inventory is the shared list of every resource WeiStack holds:
// each service reports its own, with their tags and how they relate to
// each other, and the inventory checks, completes and joins the reports.
//
// The shapes follow Huawei Cloud's Config service (RMS), which lists an
// account's resources and their relationships: the console, the MCP
// server and an emulated Config read the same inventory.
//
// What a service reports:
//   - every resource that belongs to an account and has its own ID,
//     including those the cloud makes for it, such as a project's default
//     security group; not what all accounts share (public images, system
//     policies), nor jobs, tasks or credentials;
//   - the relationships it knows from its own records, from whichever end
//     holds them: the inventory adds the other end (RelationType.Inverse),
//     and lists a relationship reported from both ends once;
//   - only relationships Config documents (Allowed).
//
// An inventory is read service by service, so it is not a snapshot of one
// instant: a resource created or deleted while it is read may be missing
// or listed.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"time"
)

// State is a resource's provisioning state, as Config documents
// provisioning_state (api-rms/rms_04_0104).
type State string

// The provisioning states.
const (
	Succeeded  State = "Succeeded"
	Failed     State = "Failed"
	Canceled   State = "Canceled"
	Processing State = "Processing"
)

func (s State) valid() bool {
	switch s {
	case Succeeded, Failed, Canceled, Processing:
		return true
	}
	return false
}

// DefaultEnterpriseProject is the ID of the default enterprise project,
// which Config reports for resources in none.
const DefaultEnterpriseProject = "0"

// Resource is one resource, as a service reports it.
type Resource struct {
	Type Type
	ID   string
	Name string
	// AccountID is the account (Huawei Cloud's domain) the resource
	// belongs to. For a resource in a project, the inventory finds it
	// from the project when the service leaves it empty. It stays empty
	// for a resource no account owns: in accept mode, clients may use
	// any project ID and any access key.
	AccountID string
	// RegionID is the resource's region, and ProjectID its project, as
	// its type's Placement requires. The inventory sets GlobalRegion for
	// a Global type.
	RegionID  string
	ProjectID string
	// EnterpriseProjectID is the resource's enterprise project. Empty
	// means the default one (DefaultEnterpriseProject).
	EnterpriseProjectID string
	// Created and Updated are when the resource was created and last
	// changed. Zero means unknown; a zero Updated becomes Created.
	Created time.Time
	Updated time.Time
	// State is the resource's provisioning state. Empty means Succeeded.
	State State
	// Tags are the resource's tags. Nil means none.
	Tags map[string]string
	// Relations are the resource's relationships to others, as reported.
	// In a Snapshot, they are every relationship from the resource,
	// including those reported by the other end, and only to resources
	// in the snapshot.
	Relations []Ref
}

// Ref is a relationship from a resource to another, which is in the same
// region and project.
type Ref struct {
	Relation RelationType
	Type     Type
	ID       string
}

// Reporter is implemented by services that hold resources.
type Reporter interface {
	// ReportResources calls emit with every resource the service holds,
	// in every account, region and project, and stops at emit's first
	// error, returning it.
	ReportResources(ctx context.Context, emit func(Resource) error) error
}

// Options configure an Inventory.
type Options struct {
	// Reporters are the services that hold resources.
	Reporters []Reporter
	// Owner returns the ID of the account a project in a region belongs
	// to, if any (IAM). Nil leaves the accounts of resources in projects
	// as the services report them.
	Owner func(projectID, region string) (string, bool)
}

// Inventory joins the services' reports.
type Inventory struct {
	reporters []Reporter
	owner     func(projectID, region string) (string, bool)
}

// New returns an inventory of the reporters' resources.
func New(o Options) *Inventory {
	return &Inventory{reporters: append([]Reporter(nil), o.Reporters...), owner: o.Owner}
}

// Snapshot is the inventory as it was read.
type Snapshot struct {
	// Resources are sorted by type, region, project and ID.
	Resources []Resource
}

// ErrInvalid wraps the errors of a report that breaks the rules above:
// it is a bug in the service that reported it.
var ErrInvalid = errors.New("inventory: invalid report")

// key identifies a resource: IDs are unique only within a type, region
// and project (KPS numbers each project's key pairs from 1).
type key struct {
	typ             Type
	region, project string
	id              string
}

func (k key) String() string {
	return fmt.Sprintf("%s %q in %s/%s", k.typ, k.id, k.region, k.project)
}

func keyOf(r Resource) key {
	return key{typ: r.Type, region: r.RegionID, project: r.ProjectID, id: r.ID}
}

// edge is a relationship between two resources.
type edge struct {
	from     key
	relation RelationType
	to       key
}

// Collect reads every reporter and returns the joined, checked inventory.
// A report that breaks the rules fails the whole read with ErrInvalid.
func (inv *Inventory) Collect(ctx context.Context) (Snapshot, error) {
	var all []Resource
	index := make(map[key]int)
	edges := make(map[edge]bool)
	for _, rep := range inv.reporters {
		err := rep.ReportResources(ctx, func(r Resource) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			r, err := inv.complete(r)
			if err != nil {
				return err
			}
			k := keyOf(r)
			if _, dup := index[k]; dup {
				return fmt.Errorf("%w: %s reported twice", ErrInvalid, k)
			}
			for _, ref := range r.Relations {
				to, err := target(r, ref)
				if err != nil {
					return err
				}
				edges[edge{k, ref.Relation, to}] = true
				edges[edge{to, ref.Relation.Inverse(), k}] = true
			}
			r.Relations = nil
			index[k] = len(all)
			all = append(all, r)
			return nil
		})
		if err != nil {
			return Snapshot{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}

	// Relationships to resources that were not reported, such as a
	// public image or a resource deleted while the inventory was read,
	// are left out.
	for e := range edges {
		i, fromOK := index[e.from]
		_, toOK := index[e.to]
		if fromOK && toOK {
			all[i].Relations = append(all[i].Relations, Ref{Relation: e.relation, Type: e.to.typ, ID: e.to.id})
		}
	}
	for i := range all {
		sortRefs(all[i].Relations)
	}
	sort.Slice(all, func(i, j int) bool { return less(keyOf(all[i]), keyOf(all[j])) })
	return Snapshot{Resources: all}, nil
}

// complete checks r against its type and fills in what the inventory
// knows better than the service.
func (inv *Inventory) complete(r Resource) (Resource, error) {
	info, ok := Lookup(r.Type)
	if !ok {
		return r, fmt.Errorf("%w: unknown type %s", ErrInvalid, r.Type)
	}
	if r.ID == "" {
		return r, fmt.Errorf("%w: a %s without an ID", ErrInvalid, r.Type)
	}
	switch info.Placement {
	case InProject:
		if r.RegionID == "" || r.RegionID == GlobalRegion || r.ProjectID == "" {
			return r, fmt.Errorf("%w: %s %q needs a region and a project, has %q and %q",
				ErrInvalid, r.Type, r.ID, r.RegionID, r.ProjectID)
		}
		if r.AccountID == "" && inv.owner != nil {
			if owner, ok := inv.owner(r.ProjectID, r.RegionID); ok {
				r.AccountID = owner
			}
		}
	case InRegion:
		if r.RegionID == "" || r.RegionID == GlobalRegion || r.ProjectID != "" {
			return r, fmt.Errorf("%w: %s %q needs a region and no project, has %q and %q",
				ErrInvalid, r.Type, r.ID, r.RegionID, r.ProjectID)
		}
	case Global:
		if (r.RegionID != "" && r.RegionID != GlobalRegion) || r.ProjectID != "" {
			return r, fmt.Errorf("%w: %s %q is global, but has region %q and project %q",
				ErrInvalid, r.Type, r.ID, r.RegionID, r.ProjectID)
		}
		r.RegionID = GlobalRegion
	}
	if r.EnterpriseProjectID == "" {
		r.EnterpriseProjectID = DefaultEnterpriseProject
	}
	if r.Updated.IsZero() {
		r.Updated = r.Created
	}
	if r.State == "" {
		r.State = Succeeded
	}
	if !r.State.valid() {
		return r, fmt.Errorf("%w: %s %q has state %q", ErrInvalid, r.Type, r.ID, r.State)
	}
	if r.Tags == nil {
		r.Tags = map[string]string{}
	} else {
		r.Tags = maps.Clone(r.Tags)
	}
	return r, nil
}

// target is the resource ref points to from r.
func target(r Resource, ref Ref) (key, error) {
	if !ref.Relation.valid() {
		return key{}, fmt.Errorf("%w: %s %q has relationship type %q", ErrInvalid, r.Type, r.ID, ref.Relation)
	}
	if !Allowed(r.Type, ref.Relation, ref.Type) {
		return key{}, fmt.Errorf("%w: Config documents no %s %s %s relationship", ErrInvalid, r.Type, ref.Relation, ref.Type)
	}
	if ref.ID == "" {
		return key{}, fmt.Errorf("%w: %s %q relates to a %s without an ID", ErrInvalid, r.Type, r.ID, ref.Type)
	}
	// Every documented relationship is between types placed alike
	// (TestDocumentedRelations), so the other resource is in r's region
	// and project.
	k := key{typ: ref.Type, region: r.RegionID, project: r.ProjectID, id: ref.ID}
	return k, nil
}

func less(a, b key) bool {
	if a.typ != b.typ {
		return a.typ.String() < b.typ.String()
	}
	if a.region != b.region {
		return a.region < b.region
	}
	if a.project != b.project {
		return a.project < b.project
	}
	return a.id < b.id
}

func sortRefs(refs []Ref) {
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.Relation != b.Relation {
			return a.Relation < b.Relation
		}
		if a.Type != b.Type {
			return a.Type.String() < b.Type.String()
		}
		return a.ID < b.ID
	})
}
