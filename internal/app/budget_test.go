package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func (i *instance) send(t *testing.T, method, path string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+i.addr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

// TestDataBudget: uploads stop at -max-data-bytes, with 507, and space
// freed by deletes can be used again.
func TestDataBudget(t *testing.T) {
	t.Parallel()
	inst := startInstance(t, map[string]string{"WEISTACK_MAX_DATA_BYTES": "1048576"}) // 1 MiB
	if status, body := inst.send(t, http.MethodPut, "/obs/budget-bucket", nil); status != http.StatusOK {
		t.Fatalf("create bucket = %d %s", status, body)
	}
	small := bytes.Repeat([]byte("x"), 256<<10)
	if status, body := inst.send(t, http.MethodPut, "/obs/budget-bucket/a", small); status != http.StatusOK {
		t.Fatalf("a 256 KiB object = %d %s", status, body)
	}
	big := bytes.Repeat([]byte("y"), 1<<20)
	status, body := inst.send(t, http.MethodPut, "/obs/budget-bucket/b", big)
	if status != http.StatusInsufficientStorage || !strings.Contains(body, "WeiStack.0507") {
		t.Fatalf("a 1 MiB object over the limit = %d %s", status, body)
	}
	if status, _ := inst.send(t, http.MethodHead, "/obs/budget-bucket/b", nil); status != http.StatusNotFound {
		t.Fatalf("the refused object exists: %d", status)
	}
	// Fill the rest, to within a few bytes.
	n := 0
	for _, size := range []int{256 << 10, 16 << 10, 512, 16} {
		for {
			n++
			status, _ := inst.send(t, http.MethodPut, "/obs/budget-bucket/fill-"+strconv.Itoa(n), bytes.Repeat([]byte("z"), size))
			if status == http.StatusInsufficientStorage {
				break
			}
			if n > 200 {
				t.Fatal("the data never filled up")
			}
		}
	}
	// Other services refuse new resources too, in their own error style.
	_, services := inst.get(t, "/_weistack/services")
	var info struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(services), &info); err != nil {
		t.Fatal(err)
	}
	status, body = inst.send(t, http.MethodPost, "/vpc/v1/"+info.ProjectID+"/vpcs", []byte(`{"vpc":{"name":"full","cidr":"10.0.0.0/16"}}`))
	if status != http.StatusInsufficientStorage || !strings.Contains(body, "WeiStack.0507") {
		t.Fatalf("a VPC once the data is full = %d %s", status, body)
	}
	if status, _ := inst.send(t, http.MethodDelete, "/obs/budget-bucket/a", nil); status != http.StatusNoContent {
		t.Fatalf("delete = %d", status)
	}
	if status, body := inst.send(t, http.MethodPut, "/obs/budget-bucket/again", small); status != http.StatusOK {
		t.Fatalf("an object after freeing space = %d %s", status, body)
	}
}
