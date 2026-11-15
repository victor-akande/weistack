// Package actions is the catalogue of IAM actions for the operations
// WeiStack emulates: each action's name, the classic names Huawei lists
// as its aliases, its access level and the resource type it acts on.
package actions

// Level is an action's documented access level.
type Level int

// Access levels, as Huawei's action tables name them.
const (
	List Level = iota + 1
	Read
	Write
	Tagging
	PermissionManagement
)

func (l Level) String() string {
	switch l {
	case List:
		return "list"
	case Read:
		return "read"
	case Write:
		return "write"
	case Tagging:
		return "tagging"
	case PermissionManagement:
		return "permission_management"
	}
	return "unknown"
}

// Action is an IAM action.
type Action struct {
	// Name is the IAM 5.0 action, service:resourceType:operation.
	Name string
	// Aliases are its classic policy names, which classic policies and
	// roles also match.
	Aliases []string
	Level   Level
	// Resource is the resource type it acts on, such as "vpc", or "" when
	// it acts on no particular resource.
	Resource string
}

var byName = func() map[string]Action {
	m := make(map[string]Action, len(all))
	for _, a := range all {
		if _, dup := m[a.Name]; dup {
			panic("actions: duplicate action " + a.Name)
		}
		m[a.Name] = a
	}
	return m
}()

// Lookup returns the action with the given name.
func Lookup(name string) (Action, bool) {
	a, ok := byName[name]
	return a, ok
}

// MustLookup returns the action with the given name, and panics if the
// catalogue has none: services name their actions as constants, so a
// typo fails at start-up and in every test.
func MustLookup(name string) Action {
	a, ok := byName[name]
	if !ok {
		panic("actions: no action " + name)
	}
	return a
}

// All returns every action in the catalogue.
func All() []Action {
	out := make([]Action, len(all))
	copy(out, all)
	return out
}
