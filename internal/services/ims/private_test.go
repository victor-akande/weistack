package ims

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/store"
)

const (
	serverID      = "11111111-1111-4111-8111-111111111111"
	bareServerID  = "22222222-2222-4222-8222-222222222222"
	ubuntuImageID = "455b5860-f96d-5d89-baaa-ec6adb758c5b"
)

// fakeServers stands in for ECS.
type fakeServers map[string]Server

func (f fakeServers) LookupServer(_ context.Context, _, projectID, id string) (Server, error) {
	if s, ok := f[projectID+"/"+id]; ok {
		return s, nil
	}
	return Server{}, ErrServerNotFound
}

func withServers(e *env) *env {
	e.svc.SetServers(fakeServers{
		testProject + "/" + serverID:     {ID: serverID, ImageID: ubuntuImageID},
		testProject + "/" + bareServerID: {ID: bareServerID, SystemDiskGB: 100},
	})
	return e
}

// settle lets one lifecycle step complete.
func (e *env) settle(t *testing.T) {
	t.Helper()
	e.clock.Advance(testDelay)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.engine.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle: %v", err)
	}
}

func createBody(name string) string {
	return fmt.Sprintf(`{"name": %q, "description": "Create an image from a server", "instance_id": %q}`, name, serverID)
}

// mustCreateImage creates a private image and waits until it is active.
func (e *env) mustCreateImage(t *testing.T, name string) Image {
	t.Helper()
	status, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody(name))
	if status != http.StatusOK {
		t.Fatalf("creating image %q: %d %s", name, status, out)
	}
	job, err := e.svc.GetJob(t.Context(), testTenant, decodeInto[createImageResponse](t, out).JobID)
	if err != nil {
		t.Fatal(err)
	}
	e.settle(t)
	e.settle(t)
	img, err := e.svc.GetImage(t.Context(), testTenant, job.Entities.ImageID)
	if err != nil || img.Status != StatusActive {
		t.Fatalf("image %q after creation: %+v, %v", name, img, err)
	}
	return img
}

func codeOf(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestPrivateImageLifecycleMatchesGoldenFiles(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))
	jobPath := func(id string) string { return "/v1/" + testProject + "/jobs/" + id }

	out := e.expect(t, "create_image", http.MethodPost, "/v2/cloudimages/action", createBody("ims_test"))
	jobID := decodeInto[createImageResponse](t, out).JobID

	out = e.expect(t, "show_job_running", http.MethodGet, jobPath(jobID), "")
	imageID := decodeInto[Job](t, out).Entities.ImageID
	imagePath := "/v2/images/" + imageID

	// queued: visible, but neither updatable nor deletable yet.
	e.expect(t, "show_private_image_queued", http.MethodGet, imagePath, "")
	e.expect(t, "error_img_0046", http.MethodPatch, "/v2/cloudimages/"+imageID, `[{"op": "replace", "path": "/name", "value": "x"}]`)
	e.expect(t, "error_img_0090", http.MethodDelete, imagePath, "")

	// saving: the job is still running.
	e.settle(t)
	if img, _ := e.svc.GetImage(t.Context(), testTenant, imageID); img.Status != StatusSaving {
		t.Fatalf("status after one step = %q, want saving", img.Status)
	}
	e.expect(t, "show_job_running", http.MethodGet, jobPath(jobID), "")
	e.expect(t, "error_img_0090", http.MethodDelete, imagePath, "")

	// active.
	e.settle(t)
	e.expect(t, "show_private_image_active", http.MethodGet, imagePath, "")
	e.expect(t, "show_job_success", http.MethodGet, jobPath(jobID), "")

	// It appears among the caller's private images, newest first overall.
	if got := e.names(t, "?__imagetype=private"); got != "ims_test" {
		t.Errorf("private images = %q", got)
	}
	if got := e.names(t, "?limit=1"); got != "ims_test +more" {
		t.Errorf("newest image = %q", got)
	}

	e.expect(t, "update_image", http.MethodPatch, "/v2/cloudimages/"+imageID,
		`[{"op": "replace", "path": "/name", "value": "ims_test_2"}, {"op": "add", "path": "/__description", "value": "renamed"}]`)

	e.expect(t, "delete_image", http.MethodDelete, imagePath, "")
	e.expect(t, "error_image_not_found", http.MethodGet, imagePath, "")
	e.expect(t, "error_image_not_found", http.MethodDelete, imagePath, "")
	e.expect(t, "error_image_not_found", http.MethodPatch, "/v2/cloudimages/"+imageID, `[{"op": "replace", "path": "/name", "value": "x"}]`)

	// The job record outlives the image.
	e.expect(t, "show_job_success", http.MethodGet, jobPath(jobID), "")
}

func TestCreateImageValidation(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))
	e.mustCreateImage(t, "taken")

	body := func(fields string) string {
		return fmt.Sprintf(`{"instance_id": %q, %s}`, serverID, fields)
	}
	tests := []struct {
		name, body, golden string
	}{
		{"empty body", ``, "error_img_0007"},
		{"malformed", `{"name": `, "error_invalid_request"},
		{"wrong type", `{"name": 7}`, "error_invalid_request"},
		{"missing name", body(`"description": "x"`), "error_img_0013"},
		{"name too long", body(`"name": "` + strings.Repeat("n", 129) + `"`), "error_img_0002"},
		{"name with slash", body(`"name": "a/b"`), "error_img_0003"},
		{"name with leading space", body(`"name": " a"`), "error_img_0003"},
		{"name with trailing space", body(`"name": "a "`), "error_img_0003"},
		{"description too long", body(`"name": "a", "description": "` + strings.Repeat("d", 1025) + `"`), "error_img_0004"},
		{"description with bracket", body(`"name": "a", "description": "<b>"`), "error_img_0054"},
		{"description with newline", body(`"name": "a", "description": "a\nb"`), "error_img_0054"},
		{"missing instance", `{"name": "a"}`, "error_img_0012"},
		{"malformed instance", `{"name": "a", "instance_id": "server-1"}`, "error_img_0012"},
		{"unknown instance", `{"name": "a", "instance_id": "` + unknownID + `"}`, "error_img_0005"},
		{"duplicate name", body(`"name": "taken"`), "error_img_0009"},
		{"negative min_ram", body(`"name": "a", "min_ram": -1`), "error_invalid_request"},
		{"max_ram below min_ram", body(`"name": "a", "min_ram": 2048, "max_ram": 1024`), "error_invalid_request"},
		{"both tag forms", body(`"name": "a", "tags": ["x"], "image_tags": [{"key": "k", "value": "v"}]`), "error_invalid_request"},
		{"empty tag", body(`"name": "a", "tags": [""]`), "error_invalid_request"},
		{"empty tag key", body(`"name": "a", "image_tags": [{"key": "", "value": "v"}]`), "error_invalid_request"},
		{"bad enterprise project", body(`"name": "a", "enterprise_project_id": "x"`), "error_invalid_request"},
		{"from a file", `{"name": "a", "image_url": "bucket:file.qcow2", "min_disk": 40}`, "error_not_implemented"},
		{"from a data disk", `{"name": "a", "volume_id": "` + unknownID + `"}`, "error_not_implemented"},
		{"with data images", body(`"name": "a", "data_images": [{"name": "d", "volume_id": "` + unknownID + `"}]`), "error_not_implemented"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPost, "/v2/cloudimages/action", tt.body)
		})
	}

	if got := e.names(t, "?__imagetype=private"); got != "taken" {
		t.Fatalf("rejected requests left images behind: %q", got)
	}
	// A server belongs to its project: another project cannot image it.
	if status, out := e.call(t, otherProject, http.MethodPost, "/v2/cloudimages/action", createBody("a")); status != 400 || !strings.Contains(string(out), "IMG.0005") {
		t.Errorf("imaging another project's server: %d %s", status, out)
	}
}

func TestCreateImageInheritsFromServer(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))

	// From a server built on the Ubuntu public image.
	img := e.mustCreateImage(t, "from ubuntu")
	if img.Platform != "Ubuntu" || img.OSVersion != "Ubuntu 22.04 server 64bit" || img.MinDisk != 40 || img.MinRAM != 1024 ||
		img.DataOrigin != "instance,"+serverID || img.Owner != testProject || img.Protected || img.ActiveAt == nil {
		t.Errorf("image = %+v", img)
	}

	// From a server whose source image is unknown, with explicit options.
	status, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", fmt.Sprintf(`{
		"name": "custom", "instance_id": %q, "min_ram": 2048, "max_ram": 8192,
		"enterprise_project_id": "0aad99bc-f5f6-4f78-8404-c598d76b0ed2",
		"image_tags": [{"key": "env", "value": "prod"}, {"key": "team", "value": ""}]}`, bareServerID))
	if status != http.StatusOK {
		t.Fatalf("create: %d %s", status, out)
	}
	job, _ := e.svc.GetJob(t.Context(), testTenant, decodeInto[createImageResponse](t, out).JobID)
	custom, err := e.svc.GetImage(t.Context(), testTenant, job.Entities.ImageID)
	if err != nil {
		t.Fatal(err)
	}
	if custom.Platform != "Other" || custom.MinDisk != 100 || custom.MinRAM != 2048 || custom.MaxRAM != "8192" ||
		custom.EnterpriseProjectID == "0" || strings.Join(custom.Tags, ",") != "env=prod,team=" {
		t.Errorf("image = %+v", custom)
	}

	if got := e.names(t, "?tag=env%3Dprod"); got != "custom" {
		t.Errorf("filter by tag = %q", got)
	}
	// Plain "tags" entries are kept as given.
	status, out = e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action",
		fmt.Sprintf(`{"name": "tagged", "instance_id": %q, "tags": ["aaa.111", "bbb"]}`, serverID))
	if status != http.StatusOK {
		t.Fatalf("create with tags: %d %s", status, out)
	}
	if got := e.names(t, "?tag=aaa.111"); got != "tagged" {
		t.Errorf("filter by plain tag = %q", got)
	}
}

func TestWithoutECSNoServerExists(t *testing.T) {
	t.Parallel()
	e := newEnv(t) // no ServerLookup installed
	e.expect(t, "error_img_0005", http.MethodPost, "/v2/cloudimages/action", createBody("a"))
}

func TestUpdateImage(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))
	img := e.mustCreateImage(t, "one")
	e.mustCreateImage(t, "two")
	path := "/v2/cloudimages/" + img.ID
	op := func(op, attr, value string) string {
		if value == "" {
			return fmt.Sprintf(`[{"op": %q, "path": %q}]`, op, attr)
		}
		return fmt.Sprintf(`[{"op": %q, "path": %q, "value": %s}]`, op, attr, value)
	}

	e.clock.Advance(time.Minute)
	valid := []struct {
		body  string
		check func(Image) bool
	}{
		{op("replace", "/min_ram", `"2048"`), func(i Image) bool { return i.MinRAM == 2048 }},
		{op("replace", "/max_ram", `4096`), func(i Image) bool { return i.MaxRAM == "4096" }}, // a JSON number
		{op("remove", "/max_ram", ""), func(i Image) bool { return i.MaxRAM == "" }},
		{op("remove", "/min_ram", ""), func(i Image) bool { return i.MinRAM == 0 }},
		{op("replace", "/hw_firmware_type", `"uefi"`), func(i Image) bool { return i.HwFirmwareType == "uefi" }},
		{op("add", "/__description", `"hello"`), func(i Image) bool { return i.Description == "hello" }},
		{op("remove", "/__description", ""), func(i Image) bool { return i.Description == "" }},
		{op("REPLACE", "/enterprise_project_id", `"0aad99bc-f5f6-4f78-8404-c598d76b0ed2"`), func(i Image) bool { return i.EnterpriseProjectID != "0" }},
		{op("replace", "/name", `"one"`), func(i Image) bool { return i.Name == "one" }}, // its own name
	}
	for _, tt := range valid {
		status, out := e.call(t, testProject, http.MethodPatch, path, tt.body)
		if status != http.StatusOK {
			t.Errorf("%s: %d %s", tt.body, status, out)
			continue
		}
		got := decodeInto[Image](t, out)
		if !tt.check(got) {
			t.Errorf("%s: result %+v", tt.body, got)
		}
		if time.Time(got.UpdatedAt).Equal(time.Time(got.CreatedAt)) {
			t.Errorf("%s: updated_at did not move", tt.body)
		}
	}

	invalid := []struct{ name, body, golden string }{
		{"empty body", ``, "error_img_0007"},
		{"empty list", `[]`, "error_img_0007"},
		{"not a list", `{"op": "replace"}`, "error_invalid_request"},
		{"bad op", op("move", "/name", `"x"`), "error_invalid_request"},
		{"path without slash", op("replace", "name", `"x"`), "error_invalid_request"},
		{"missing value", op("replace", "/name", ""), "error_invalid_request"},
		{"value is an object", op("replace", "/name", `{}`), "error_invalid_request"},
		{"remove name", op("remove", "/name", ""), "error_img_0013"},
		{"bad name", op("replace", "/name", `"a/b"`), "error_img_0003"},
		{"long name", op("replace", "/name", `"`+strings.Repeat("n", 129)+`"`), "error_img_0002"},
		{"name taken", op("replace", "/name", `"two"`), "error_img_0009"},
		{"bad description", op("replace", "/__description", `"<"`), "error_img_0054"},
		{"bad min_ram", op("replace", "/min_ram", `"lots"`), "error_invalid_request"},
		{"bad max_ram", op("replace", "/max_ram", `"-5"`), "error_invalid_request"},
		{"max below min", `[{"op": "replace", "path": "/min_ram", "value": "4096"}, {"op": "replace", "path": "/max_ram", "value": "1024"}]`, "error_invalid_request"},
		{"bad firmware", op("replace", "/hw_firmware_type", `"efi"`), "error_invalid_request"},
		{"bad enterprise project", op("replace", "/enterprise_project_id", `"x"`), "error_invalid_request"},
		{"unsupported attribute", op("replace", "/__support_kvm", `"true"`), "error_not_implemented"},
	}
	before, _ := e.svc.GetImage(t.Context(), testTenant, img.ID)
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			e.expect(t, tt.golden, http.MethodPatch, path, tt.body)
		})
	}
	// All-or-nothing: a failing operation after a valid one changes nothing.
	e.expect(t, "error_img_0003", http.MethodPatch, path,
		`[{"op": "replace", "path": "/__description", "value": "applied?"}, {"op": "replace", "path": "/name", "value": "a/b"}]`)
	after, _ := e.svc.GetImage(t.Context(), testTenant, img.ID)
	if after.Description != before.Description || after.Name != before.Name {
		t.Fatalf("a rejected update was partly applied: %+v", after)
	}

	// Public images belong to the platform.
	e.expect(t, "error_img_0047", http.MethodPatch, "/v2/cloudimages/"+ubuntuImageID, op("replace", "/name", `"mine"`))
	e.expect(t, "error_img_0094", http.MethodDelete, "/v2/images/"+ubuntuImageID, "")
	// Another project cannot touch, or even see, this image.
	if status, _ := e.call(t, otherProject, http.MethodPatch, path, op("replace", "/name", `"x"`)); status != http.StatusNotFound {
		t.Errorf("another project updating the image: %d", status)
	}
	if status, _ := e.call(t, otherProject, http.MethodDelete, "/v2/images/"+img.ID, ""); status != http.StatusNotFound {
		t.Errorf("another project deleting the image: %d", status)
	}
}

func TestProtectedImageCannotBeDeleted(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))
	img := e.mustCreateImage(t, "keep")
	if _, err := e.svc.privateImages(testTenant).Update(t.Context(), img.ID, func(i *Image) error { i.Protected = true; return nil }); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "error_img_0091", http.MethodDelete, "/v2/images/"+img.ID, "")
	// A body on DELETE is accepted and ignored.
	if status, _ := e.call(t, testProject, http.MethodDelete, "/v2/images/"+img.ID, `{"delete_backup": true}`); status != http.StatusBadRequest {
		t.Errorf("delete with body: %d", status)
	}
}

func TestJobs(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))

	e.expect(t, "error_img_0023", http.MethodGet, "/v1/"+testProject+"/jobs/"+strings.Repeat("0", 32), "")

	_, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody("a"))
	jobID := decodeInto[createImageResponse](t, out).JobID
	// Jobs are per project.
	if status, _ := e.call(t, testProject, http.MethodGet, "/v1/"+otherProject+"/jobs/"+jobID, ""); status != http.StatusBadRequest {
		t.Errorf("another project reading the job: %d", status)
	}

	job, err := e.svc.GetJob(t.Context(), testTenant, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(jobTimeLayout, job.BeginTime); err != nil || job.EndTime != "" {
		t.Errorf("running job times: begin %q end %q", job.BeginTime, job.EndTime)
	}
	e.settle(t)
	e.settle(t)
	job, _ = e.svc.GetJob(t.Context(), testTenant, jobID)
	begin, _ := time.Parse(jobTimeLayout, job.BeginTime)
	end, err := time.Parse(jobTimeLayout, job.EndTime)
	if err != nil || end.Sub(begin) != 2*testDelay || job.Status != JobSuccess {
		t.Errorf("finished job: %+v", job)
	}
}

type failKind string

func (f failKind) Fault(kind, _ string) error {
	if kind == string(f) {
		return errors.New("injected storage failure")
	}
	return nil
}

func TestCreationFaultKillsTheImageAndFailsTheJob(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{taskImageSave, taskImageActivate} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			engine := lifecycle.New(lifecycle.Options{Logger: log, Faults: failKind(kind)})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go engine.Run(ctx)

			svc, err := New(Deps{
				Store: store.NewMemory(), Engine: engine, IDs: ids.New(), Logger: log, DefaultProjectID: testProject,
				Servers: fakeServers{testProject + "/" + serverID: {ID: serverID}},
			})
			if err != nil {
				t.Fatal(err)
			}
			job, err := svc.CreateImage(ctx, testTenant, CreateImageOption{Name: "doomed", InstanceID: serverID})
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.WaitIdle(ctx); err != nil {
				t.Fatal(err)
			}

			img, err := svc.GetImage(ctx, testTenant, job.Entities.ImageID)
			if err != nil || img.Status != StatusKilled {
				t.Fatalf("image = %+v, %v; want status killed", img, err)
			}
			job, _ = svc.GetJob(ctx, testTenant, job.JobID)
			if job.Status != JobFail || job.ErrorCode == nil || *job.ErrorCode != "IMG.0014" ||
				job.FailReason == nil || !strings.Contains(*job.FailReason, "injected") || job.EndTime == "" {
				t.Fatalf("job = %+v", job)
			}
			// A killed image can be cleaned up.
			if err := svc.DeleteImage(ctx, testTenant, img.ID); err != nil {
				t.Fatalf("deleting a killed image: %v", err)
			}
		})
	}
}

func TestFailedJobMatchesGoldenFile(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))
	_, out := e.call(t, testProject, http.MethodPost, "/v2/cloudimages/action", createBody("a"))
	jobID := decodeInto[createImageResponse](t, out).JobID
	job, _ := e.svc.GetJob(t.Context(), testTenant, jobID)
	e.svc.failCreation(t.Context(), testTenant, job.Entities.ImageID, jobID, errors.New("disk full"))
	e.expect(t, "show_job_fail", http.MethodGet, "/v1/"+testProject+"/jobs/"+jobID, "")
}

// Two clients racing for one image name: exactly one wins.
func TestConcurrentCreatesWithOneName(t *testing.T) {
	t.Parallel()
	e := withServers(newEnv(t))

	const workers = 40
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ok, dups int
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.CreateImage(t.Context(), testTenant, CreateImageOption{Name: "only-one", InstanceID: serverID})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case codeOf(err) == "IMG.0009":
				dups++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || dups != workers-1 {
		t.Fatalf("%d creates succeeded, %d rejected; want 1 and %d", ok, dups, workers-1)
	}
}

func TestResumeFinishesInterruptedCreations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "weistack.db")
	st, err := store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := withServers(newEnvWith(t, st, ""))
	create := func(name string) Job {
		t.Helper()
		job, err := first.svc.CreateImage(t.Context(), testTenant, CreateImageOption{Name: name, InstanceID: serverID})
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	saving := create("was-saving")
	first.settle(t) // queued -> saving
	queued := create("was-queued")
	orphan := create("image-deleted")
	stale := create("job-not-closed")
	// Simulate odd states a crash can leave behind.
	if err := first.svc.privateImages(testTenant).Delete(t.Context(), orphan.Entities.ImageID); err != nil {
		t.Fatal(err)
	}
	if !first.svc.setStatus(t.Context(), testTenant, stale.Entities.ImageID, StatusActive) {
		t.Fatal("setStatus failed")
	}
	first.engine.CancelAll() // the process "dies" with transitions pending
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = store.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, st, "")
	if err := e.svc.Resume(t.Context()); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	e.settle(t)
	e.settle(t)

	for name, job := range map[string]Job{"was-saving": saving, "was-queued": queued, "job-not-closed": stale} {
		img, err := e.svc.GetImage(t.Context(), testTenant, job.Entities.ImageID)
		if err != nil || img.Status != StatusActive {
			t.Errorf("%s: image %+v, %v; want active", name, img.Status, err)
		}
		if got, _ := e.svc.GetJob(t.Context(), testTenant, job.JobID); got.Status != JobSuccess {
			t.Errorf("%s: job status %q, want SUCCESS", name, got.Status)
		}
	}
	if got, _ := e.svc.GetJob(t.Context(), testTenant, orphan.JobID); got.Status != JobFail {
		t.Errorf("job of a vanished image: status %q, want FAIL", got.Status)
	}

	// Corrupt job records are reported, not skipped.
	scope := store.Scope{Region: testRegion, ProjectID: testProject, Kind: kindJob}
	if _, err := e.store.Put(t.Context(), scope, "bad", []byte("not json")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Resume(t.Context()); err == nil {
		t.Fatal("Resume ignored a corrupt job record")
	}
}
