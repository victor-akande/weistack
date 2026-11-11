package sdk

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

// writeRandomFile writes size pseudo-random bytes to path and returns
// their hex MD5. The content is deterministic, so a failure reproduces.
func writeRandomFile(t *testing.T, path string, size int64) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	src := mrand.NewChaCha8([32]byte{'w', 'e', 'i', 's', 't', 'a', 'c', 'k'})
	h := md5.New()
	if _, err := io.CopyN(io.MultiWriter(f, h), src, size); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestOBSLargeMultipartUpload is the large-file half of plan scenario 3:
// a 100 MB file sent with the OBS SDK's resumable UploadFile, which
// uploads parts in parallel and keeps a checkpoint file, then read back
// whole and by range.
func TestOBSLargeMultipartUpload(t *testing.T) {
	const (
		size     = 100 << 20
		partSize = 10 << 20
	)
	dir := t.TempDir()
	file := filepath.Join(dir, "large.bin")
	wantMD5 := writeRandomFile(t, file, size)

	c := newOBS(t, "AKmultipart-large", obs.SignatureObs, false)
	bucket := "sdk-multipart-large"
	if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	in := &obs.UploadFileInput{
		UploadFile:       file,
		PartSize:         partSize,
		TaskNum:          4,
		EnableCheckpoint: true,
		CheckpointFile:   filepath.Join(dir, "large.checkpoint"),
	}
	in.Bucket, in.Key = bucket, "backups/large.bin"
	in.ContentType = "application/octet-stream"
	in.Metadata = map[string]string{"source": "uploadfile"}
	out, err := c.UploadFile(in)
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	if !strings.HasSuffix(strings.Trim(out.ETag, `"`), fmt.Sprintf("-%d", size/partSize)) {
		t.Errorf("ETag %s is not a %d-part multipart ETag", out.ETag, size/partSize)
	}
	if _, err := os.Stat(in.CheckpointFile); !os.IsNotExist(err) {
		t.Errorf("the SDK left its checkpoint file behind (%v): the upload did not finish cleanly", err)
	}

	meta, err := c.GetObjectMetadata(&obs.GetObjectMetadataInput{Bucket: bucket, Key: in.Key})
	if err != nil || meta.ContentLength != size || meta.Metadata["source"] != "uploadfile" {
		t.Fatalf("GetObjectMetadata = %+v, %v", meta, err)
	}

	// Read it all back and compare digests.
	get := &obs.GetObjectInput{}
	get.Bucket, get.Key = bucket, in.Key
	whole, err := c.GetObject(get)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	h := md5.New()
	n, err := io.Copy(h, whole.Body)
	whole.Body.Close()
	if err != nil || n != size || hex.EncodeToString(h.Sum(nil)) != wantMD5 {
		t.Fatalf("download: %d bytes, err %v; content does not match the file", n, err)
	}

	// A range straddling two parts, compared with the file itself.
	start := int64(3*partSize - 512)
	ranged := &obs.GetObjectInput{RangeStart: start, RangeEnd: start + 1023}
	ranged.Bucket, ranged.Key = bucket, in.Key
	part, err := c.GetObject(ranged)
	if err != nil {
		t.Fatalf("ranged GetObject: %v", err)
	}
	got, _ := io.ReadAll(part.Body)
	part.Body.Close()
	want := make([]byte, 1024)
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.ReadAt(want, start)
	f.Close()
	if !bytes.Equal(got, want) {
		t.Fatalf("ranged download across a part boundary does not match the file")
	}

	if _, err := c.DeleteObject(&obs.DeleteObjectInput{Bucket: bucket, Key: in.Key}); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, err := c.DeleteBucket(bucket); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
}

// TestOBSMultipartCalls drives each multipart operation of the OBS SDK
// directly, in both dialects.
func TestOBSMultipartCalls(t *testing.T) {
	for _, mode := range []struct {
		name      string
		signature obs.SignatureType
	}{{"obs-dialect", obs.SignatureObs}, {"s3-dialect", obs.SignatureV2}} {
		t.Run(mode.name, func(t *testing.T) {
			c := newOBS(t, "AKmultipart-"+mode.name, mode.signature, false)
			bucket := "sdk-multipart-" + mode.name
			if _, err := c.CreateBucket(&obs.CreateBucketInput{Bucket: bucket}); err != nil {
				t.Fatalf("CreateBucket: %v", err)
			}

			initIn := &obs.InitiateMultipartUploadInput{}
			initIn.Bucket, initIn.Key = bucket, "assembled.txt"
			initIn.ContentType = "text/plain"
			initIn.Metadata = map[string]string{"parts": "two"}
			started, err := c.InitiateMultipartUpload(initIn)
			if err != nil || started.UploadId == "" || started.Key != "assembled.txt" {
				t.Fatalf("InitiateMultipartUpload = %+v, %v", started, err)
			}

			first := strings.Repeat("a", 100<<10) // the OBS minimum for a non-last part
			second := "and the rest"
			var parts []obs.Part
			for i, body := range []string{first, second} {
				up, err := c.UploadPart(&obs.UploadPartInput{
					Bucket: bucket, Key: "assembled.txt", UploadId: started.UploadId,
					PartNumber: i + 1, Body: strings.NewReader(body),
				})
				if err != nil {
					t.Fatalf("UploadPart(%d): %v", i+1, err)
				}
				parts = append(parts, obs.Part{PartNumber: i + 1, ETag: up.ETag})
			}

			listed, err := c.ListParts(&obs.ListPartsInput{Bucket: bucket, Key: "assembled.txt", UploadId: started.UploadId})
			if err != nil || len(listed.Parts) != 2 || listed.Parts[1].Size != int64(len(second)) {
				t.Fatalf("ListParts = %+v, %v", listed, err)
			}
			uploads, err := c.ListMultipartUploads(&obs.ListMultipartUploadsInput{Bucket: bucket})
			if err != nil || len(uploads.Uploads) != 1 || uploads.Uploads[0].UploadId != started.UploadId {
				t.Fatalf("ListMultipartUploads = %+v, %v", uploads, err)
			}

			// A bucket holding parts cannot be deleted.
			_, err = c.DeleteBucket(bucket)
			wantOBSError(t, err, 409, "BucketNotEmpty")

			done, err := c.CompleteMultipartUpload(&obs.CompleteMultipartUploadInput{
				Bucket: bucket, Key: "assembled.txt", UploadId: started.UploadId, Parts: parts,
			})
			if err != nil || !strings.HasSuffix(strings.Trim(done.ETag, `"`), "-2") || done.Key != "assembled.txt" {
				t.Fatalf("CompleteMultipartUpload = %+v, %v", done, err)
			}
			get := &obs.GetObjectInput{}
			get.Bucket, get.Key = bucket, "assembled.txt"
			obj, err := c.GetObject(get)
			if err != nil {
				t.Fatalf("GetObject: %v", err)
			}
			body, _ := io.ReadAll(obj.Body)
			obj.Body.Close()
			if string(body) != first+second || obj.ContentType != "text/plain" || obj.Metadata["parts"] != "two" {
				t.Fatalf("assembled object: %d bytes, type %q, metadata %v", len(body), obj.ContentType, obj.Metadata)
			}

			// Too small a non-last part fails at completion, as documented.
			small := &obs.InitiateMultipartUploadInput{}
			small.Bucket, small.Key = bucket, "too-small.txt"
			s, err := c.InitiateMultipartUpload(small)
			if err != nil {
				t.Fatal(err)
			}
			var smallParts []obs.Part
			for i := 1; i <= 2; i++ {
				up, err := c.UploadPart(&obs.UploadPartInput{Bucket: bucket, Key: "too-small.txt", UploadId: s.UploadId, PartNumber: i, Body: strings.NewReader("tiny")})
				if err != nil {
					t.Fatal(err)
				}
				smallParts = append(smallParts, obs.Part{PartNumber: i, ETag: up.ETag})
			}
			_, err = c.CompleteMultipartUpload(&obs.CompleteMultipartUploadInput{Bucket: bucket, Key: "too-small.txt", UploadId: s.UploadId, Parts: smallParts})
			wantOBSError(t, err, 400, "EntityTooSmall")

			if _, err := c.AbortMultipartUpload(&obs.AbortMultipartUploadInput{Bucket: bucket, Key: "too-small.txt", UploadId: s.UploadId}); err != nil {
				t.Fatalf("AbortMultipartUpload: %v", err)
			}
			_, err = c.ListParts(&obs.ListPartsInput{Bucket: bucket, Key: "too-small.txt", UploadId: s.UploadId})
			wantOBSError(t, err, 404, "NoSuchUpload")

			if _, err := c.DeleteObject(&obs.DeleteObjectInput{Bucket: bucket, Key: "assembled.txt"}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.DeleteBucket(bucket); err != nil {
				t.Fatalf("DeleteBucket: %v", err)
			}
		})
	}
}

// TestS3MultipartCalls drives multipart through the AWS SDK, whose
// clients require 5 MiB parts.
func TestS3MultipartCalls(t *testing.T) {
	ctx := context.Background()
	c := newS3(t, "AKaws-multipart", false)
	bucket := aws.String("sdk-aws-multipart")
	if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	key := aws.String("video.mp4")

	started, err := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: bucket, Key: key, ContentType: aws.String("video/mp4"), Metadata: map[string]string{"codec": "h264"},
	})
	if err != nil || aws.ToString(started.UploadId) == "" {
		t.Fatalf("CreateMultipartUpload = %+v, %v", started, err)
	}

	bodies := [][]byte{bytes.Repeat([]byte{'x'}, 5<<20), []byte("end of video")}
	var completed []types.CompletedPart
	for i, body := range bodies {
		up, err := c.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: bucket, Key: key, UploadId: started.UploadId,
			PartNumber: aws.Int32(int32(i + 1)), Body: bytes.NewReader(body),
		})
		if err != nil {
			t.Fatalf("UploadPart(%d): %v", i+1, err)
		}
		completed = append(completed, types.CompletedPart{PartNumber: aws.Int32(int32(i + 1)), ETag: up.ETag})
	}

	parts, err := c.ListParts(ctx, &s3.ListPartsInput{Bucket: bucket, Key: key, UploadId: started.UploadId})
	if err != nil || len(parts.Parts) != 2 || aws.ToInt64(parts.Parts[0].Size) != 5<<20 {
		t.Fatalf("ListParts = %+v, %v", parts, err)
	}
	list, err := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: bucket})
	if err != nil || len(list.Uploads) != 1 || aws.ToString(list.Uploads[0].Key) != "video.mp4" {
		t.Fatalf("ListMultipartUploads = %+v, %v", list, err)
	}

	done, err := c.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: bucket, Key: key, UploadId: started.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil || !strings.HasSuffix(strings.Trim(aws.ToString(done.ETag), `"`), "-2") {
		t.Fatalf("CompleteMultipartUpload = %+v, %v", done, err)
	}
	head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: bucket, Key: key})
	if err != nil || aws.ToInt64(head.ContentLength) != int64(len(bodies[0])+len(bodies[1])) ||
		aws.ToString(head.ContentType) != "video/mp4" || head.Metadata["codec"] != "h264" {
		t.Fatalf("HeadObject = %+v, %v", head, err)
	}

	// Abort, and the upload is gone.
	other, err := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: bucket, Key: aws.String("abandoned")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: bucket, Key: aws.String("abandoned"), UploadId: other.UploadId}); err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}
	_, err = c.UploadPart(ctx, &s3.UploadPartInput{Bucket: bucket, Key: aws.String("abandoned"), UploadId: other.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("x")})
	wantS3Error(t, err, "NoSuchUpload")

	if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: bucket, Key: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: bucket}); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
}
