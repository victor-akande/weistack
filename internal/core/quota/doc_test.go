package quota

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestDocListsEveryKey keeps docs/quotas.md in step with the table.
func TestDocListsEveryKey(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../../docs/quotas.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, k := range Keys() {
		v, src, _ := Default(k)
		val := fmt.Sprint(v)
		if v == Unlimited {
			val = "-1 (unlimited)"
		}
		if row := fmt.Sprintf("| `%s` | %s | %s |", k, val, src); !strings.Contains(doc, row) {
			t.Errorf("docs/quotas.md lacks the row %s", row)
		}
	}
}
