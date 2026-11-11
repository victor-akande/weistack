package zones

import (
	"strings"
	"testing"
)

func TestZones(t *testing.T) {
	t.Parallel()
	if got := strings.Join(Of("af-south-1"), ","); got != "af-south-1a,af-south-1b,af-south-1c" {
		t.Errorf("Of = %s", got)
	}
	if !Exists("af-south-1", "af-south-1c") || Exists("af-south-1", "af-south-1d") || Exists("af-south-1", "ap-southeast-1a") {
		t.Error("Exists is wrong")
	}
}
