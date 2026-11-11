package obs

import (
	"net/http"
	"strings"
	"testing"
)

func TestBucketConfigurationReads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/photos"), http.StatusOK)

	// What a never-configured bucket has: empty documents...
	for sub, want := range map[string]string{
		"versioning":     `<VersioningConfiguration xmlns="http://obs.myhwclouds.com/doc/2015-06-30/"></VersioningConfiguration>`,
		"logging":        `<BucketLoggingStatus xmlns="http://obs.myhwclouds.com/doc/2015-06-30/"></BucketLoggingStatus>`,
		"notification":   `<NotificationConfiguration xmlns="http://obs.myhwclouds.com/doc/2015-06-30/"></NotificationConfiguration>`,
		"quota":          `<StorageQuota>0</StorageQuota>`,
		"customdomain":   `<ListBucketCustomDomainsResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/"></ListBucketCustomDomainsResult>`,
		"requestPayment": `<Payer>BucketOwner</Payer>`,
		"storageClass":   `<StorageClass xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">STANDARD</StorageClass>`,
		"storagePolicy":  `<DefaultStorageClass>STANDARD</DefaultStorageClass>`,
		"acl":            `<Permission>FULL_CONTROL</Permission>`,
	} {
		got := e.as(t, alice, http.MethodGet, "/photos?"+sub)
		if got.Status != http.StatusOK || !strings.Contains(got.Body, want) {
			t.Errorf("GET ?%s = %d %s, want it to contain %s", sub, got.Status, got.Body, want)
		}
	}

	// ...or the specific 404 clients check for.
	for sub, code := range map[string]string{
		"policy": "NoSuchBucketPolicy", "lifecycle": "NoSuchLifecycleConfiguration", "cors": "NoSuchCORSConfiguration",
		"tagging": "NoSuchTagSet", "website": "NoSuchWebsiteConfiguration", "encryption": "NoSuchEncryptionConfiguration",
	} {
		wantError(t, e.as(t, alice, http.MethodGet, "/photos?"+sub), http.StatusNotFound, code)
	}

	// The S3 dialect has its own namespace and encryption code.
	mustStatus(t, e.as(t, bob, http.MethodPut, "/bobs"), http.StatusOK)
	if got := e.as(t, bob, http.MethodGet, "/bobs?versioning"); !strings.Contains(got.Body, `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`) {
		t.Errorf("S3 dialect versioning: %s", got.Body)
	}
	wantError(t, e.as(t, bob, http.MethodGet, "/bobs?encryption"), http.StatusNotFound, "ServerSideEncryptionConfigurationNotFoundError")

	// The bucket must exist and belong to the caller.
	wantError(t, e.as(t, alice, http.MethodGet, "/missing?versioning"), http.StatusNotFound, "NoSuchBucket")
	wantError(t, e.as(t, alice, http.MethodGet, "/missing?cors"), http.StatusNotFound, "NoSuchBucket")
	wantError(t, e.as(t, bob, http.MethodGet, "/photos?acl"), http.StatusForbidden, "AccessDenied")
	wantError(t, e.as(t, bob, http.MethodGet, "/photos?tagging"), http.StatusForbidden, "AccessDenied")
}

func TestBucketACLNamesTheOwner(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/photos"), http.StatusOK)
	got := e.as(t, alice, http.MethodGet, "/photos?acl")
	id := ownerID("AKALICE")
	if strings.Count(got.Body, "<ID>"+id+"</ID>") != 2 || !strings.Contains(got.Body, `xsi:type="CanonicalUser"`) {
		t.Fatalf("ACL = %s", got.Body)
	}
}

func TestBucketStorageInfoCountsObjects(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mustStatus(t, e.as(t, alice, http.MethodPut, "/data"), http.StatusOK)
	if got := e.as(t, alice, http.MethodGet, "/data?storageinfo"); !strings.Contains(got.Body, "<Size>0</Size><ObjectNumber>0</ObjectNumber>") {
		t.Fatalf("empty bucket: %s", got.Body)
	}
	for _, key := range []string{"a", "b/c"} {
		mustStatus(t, e.do(t, req{Method: http.MethodPut, Path: "/data/" + key, Auth: alice, Body: "12345"}), http.StatusOK)
	}
	if got := e.as(t, alice, http.MethodGet, "/data?storageinfo"); !strings.Contains(got.Body, "<Size>10</Size><ObjectNumber>2</ObjectNumber>") {
		t.Fatalf("two objects: %s", got.Body)
	}
}
