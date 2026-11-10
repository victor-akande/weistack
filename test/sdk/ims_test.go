package sdk

import (
	"testing"

	imsv2 "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2"
	ims "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ims/v2/model"
)

func newIMS(t *testing.T) *imsv2.ImsClient {
	t.Helper()
	hc, err := imsv2.ImsClientBuilder().
		WithEndpoints([]string{"http://ims." + region + ".myhuaweicloud.com"}).
		WithCredential(credentials(t)).
		WithHttpConfig(httpConfig()).
		SafeBuild()
	if err != nil {
		t.Fatalf("building IMS client: %v", err)
	}
	return imsv2.NewImsClient(hc)
}

// TestPublicImages finds a public image the way a learner's script
// would before creating a server: list with filters, then show by ID.
func TestPublicImages(t *testing.T) {
	c := newIMS(t)

	gold := ims.GetListImagesRequestImagetypeEnum().GOLD
	listed, err := c.ListImages(&ims.ListImagesRequest{
		Imagetype: &gold,
		Name:      ptr("Ubuntu 22.04 server 64bit"),
	})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if listed.Images == nil || len(*listed.Images) != 1 {
		t.Fatalf("ListImages returned %+v, want exactly the Ubuntu 22.04 image", listed.Images)
	}
	img := (*listed.Images)[0]
	if img.Id == "" || img.Name != "Ubuntu 22.04 server 64bit" || img.MinDisk != 40 || img.MinRam != 1024 || !img.Protected {
		t.Errorf("image = %+v", img)
	}
	// Values the SDK decodes into its own enum types.
	if img.Status.Value() != "active" || img.Visibility.Value() != "public" || img.Imagetype.Value() != "gold" ||
		img.OsType.Value() != "Linux" || img.Platform == nil || img.Platform.Value() != "Ubuntu" ||
		img.OsBit == nil || img.OsBit.Value() != "64" {
		t.Errorf("enum fields: status %q visibility %q type %q os %q", img.Status.Value(), img.Visibility.Value(), img.Imagetype.Value(), img.OsType.Value())
	}
	if img.OsVersion == nil || *img.OsVersion != "Ubuntu 22.04 server 64bit" || img.CreatedAt == "" || img.Self == "" {
		t.Errorf("image = %+v", img)
	}

	shown, err := c.GlanceShowImage(&ims.GlanceShowImageRequest{ImageId: img.Id})
	if err != nil {
		t.Fatalf("GlanceShowImage: %v", err)
	}
	if shown.Id == nil || *shown.Id != img.Id || shown.Name == nil || *shown.Name != img.Name ||
		shown.Status == nil || shown.Status.Value() != "active" || shown.MinDisk == nil || *shown.MinDisk != 40 {
		t.Errorf("GlanceShowImage = %+v", shown)
	}

	_, err = c.GlanceShowImage(&ims.GlanceShowImageRequest{ImageId: unknownID})
	wantError(t, err, 404, "IMG.0027")
	_, err = c.ListImages(&ims.ListImagesRequest{Limit: ptr(int32(5000))})
	wantError(t, err, 400, "IMG.0001")
}

// TestImagePaging walks the public images two at a time, following
// page_info.next_marker until it is absent.
func TestImagePaging(t *testing.T) {
	c := newIMS(t)

	gold := ims.GetListImagesRequestImagetypeEnum().GOLD
	sortKey := ims.GetListImagesRequestSortKeyEnum().NAME
	sortDir := ims.GetListImagesRequestSortDirEnum().ASC

	var (
		names  []string
		marker *string
	)
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("paging did not terminate")
		}
		res, err := c.ListImages(&ims.ListImagesRequest{
			Imagetype: &gold, SortKey: &sortKey, SortDir: &sortDir, Limit: ptr(int32(2)), Marker: marker,
		})
		if err != nil {
			t.Fatalf("ListImages: %v", err)
		}
		if res.Images != nil {
			for _, img := range *res.Images {
				names = append(names, img.Name)
			}
		}
		if res.PageInfo == nil || res.PageInfo.NextMarker == "" {
			break
		}
		marker = &res.PageInfo.NextMarker
	}

	if len(names) < 8 {
		t.Fatalf("paging returned %d public images, want at least the 8 built-in ones: %v", len(names), names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("names are not strictly ascending (duplicate or misordered): %v", names)
		}
	}
}

// TestPrivateImageErrors covers the private image operations as far as
// they go without a server to make an image of. The full create ->
// active -> update -> delete flow is exercised with ECS.
func TestPrivateImageErrors(t *testing.T) {
	c := newIMS(t)

	listed, err := c.ListImages(&ims.ListImagesRequest{Name: ptr("CentOS 7.9 64bit")})
	if err != nil || listed.Images == nil || len(*listed.Images) != 1 {
		t.Fatalf("ListImages = %+v, %v", listed, err)
	}
	public := (*listed.Images)[0].Id

	_, err = c.CreateImage(&ims.CreateImageRequest{Body: &ims.CreateImageRequestBody{
		Name: ptr("from-nowhere"), InstanceId: ptr(unknownID),
	}})
	wantError(t, err, 400, "IMG.0005")
	_, err = c.CreateImage(&ims.CreateImageRequest{Body: &ims.CreateImageRequestBody{InstanceId: ptr(unknownID)}})
	wantError(t, err, 400, "IMG.0013")

	replace := ims.GetUpdateImageRequestBodyOpEnum().REPLACE
	_, err = c.UpdateImage(&ims.UpdateImageRequest{ImageId: public, Body: &[]ims.UpdateImageRequestBody{
		{Op: replace, Path: "/name", Value: "mine-now"},
	}})
	wantError(t, err, 400, "IMG.0047")

	_, err = c.GlanceDeleteImage(&ims.GlanceDeleteImageRequest{ImageId: public})
	wantError(t, err, 400, "IMG.0094")
	_, err = c.GlanceDeleteImage(&ims.GlanceDeleteImageRequest{ImageId: unknownID})
	wantError(t, err, 404, "IMG.0027")

	_, err = c.ShowJob(&ims.ShowJobRequest{JobId: "00000000000000000000000000000000"})
	wantError(t, err, 400, "IMG.0023")
}
