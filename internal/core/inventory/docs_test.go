package inventory

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// TestDocsListEveryTypeAndRelation: docs/inventory.md lists exactly the
// catalogue and the documented relationships.
func TestDocsListEveryTypeAndRelation(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../../docs/inventory.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	typeRow := regexp.MustCompile("(?m)^\\| `([a-z]+\\.[A-Za-z0-9]+)` \\| [^|]+ \\| (Documented|WeiStack's) \\|$")
	var gotTypes, wantTypes []string
	for _, m := range typeRow.FindAllStringSubmatch(doc, -1) {
		gotTypes = append(gotTypes, m[1]+" "+m[2])
	}
	for _, info := range Types() {
		mark := "WeiStack's"
		if info.Documented {
			mark = "Documented"
		}
		wantTypes = append(wantTypes, info.Type.String()+" "+mark)
	}
	if !reflect.DeepEqual(gotTypes, wantTypes) {
		t.Errorf("docs/inventory.md types:\n%v\nwant (sorted):\n%v", gotTypes, wantTypes)
	}

	relationRow := regexp.MustCompile("(?m)^\\| `([a-z]+\\.[A-Za-z0-9]+)` \\| `([A-Za-z]+)` \\| `([a-z]+\\.[A-Za-z0-9]+)` \\|$")
	var gotPairs, wantPairs []string
	for _, m := range relationRow.FindAllStringSubmatch(doc, -1) {
		gotPairs = append(gotPairs, m[1]+" "+m[2]+" "+m[3])
	}
	for _, p := range documented {
		wantPairs = append(wantPairs, p.from.String()+" "+string(p.relation)+" "+p.to.String())
	}
	sort.Strings(gotPairs)
	sort.Strings(wantPairs)
	if !reflect.DeepEqual(gotPairs, wantPairs) {
		t.Errorf("docs/inventory.md relationships:\n%v\nwant:\n%v", gotPairs, wantPairs)
	}
}
