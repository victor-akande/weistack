package ims

import (
	"crypto/sha1" //nolint:gosec // name-based UUIDs (RFC 4122 version 5) are defined on SHA-1
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

//go:embed seed/images.yaml
var builtinImages []byte

// seedFileName is the file looked for in the seed directory.
const seedFileName = "images.yaml"

// publicOwner is the project that owns public images.
const publicOwner = "00000000000000000000000000000000"

// seedEpoch is the creation time given to seeded images, fixed so that
// listings are identical on every run.
var seedEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// emptyChecksum is the MD5 of no data, which the API reference shows for
// public images.
const emptyChecksum = "d41d8cd98f00b204e9800998ecf8427e"

type seedFile struct {
	Images []seedImage `yaml:"images"`
}

type seedImage struct {
	Name      string `yaml:"name"`
	OSVersion string `yaml:"os_version"`
	Platform  string `yaml:"platform"`
	OSType    string `yaml:"os_type"`
	MinDisk   int    `yaml:"min_disk"`
	MinRAM    int    `yaml:"min_ram"`
	Arch      string `yaml:"arch"`
	Firmware  string `yaml:"firmware"`
	ID        string `yaml:"id"`
}

// loadSeedImages returns the built-in public images, extended by
// images.yaml in seedDir when that file exists. An entry in the file
// replaces a built-in image of the same name.
func loadSeedImages(seedDir string) ([]Image, error) {
	entries, err := parseSeed(builtinImages, "built-in images.yaml")
	if err != nil {
		return nil, err
	}
	if seedDir != "" {
		path := filepath.Join(seedDir, seedFileName)
		raw, err := os.ReadFile(path) //nolint:gosec // operator-chosen seed directory
		switch {
		case err == nil:
			extra, err := parseSeed(raw, path)
			if err != nil {
				return nil, err
			}
			entries = mergeSeeds(entries, extra)
		case !errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("ims: reading seed file: %w", err)
		}
	}

	images := make([]Image, 0, len(entries))
	ids := map[string]string{}
	for i, e := range entries {
		img := e.image(i)
		if other, dup := ids[img.ID]; dup {
			return nil, fmt.Errorf("ims: seed images %q and %q have the same ID %s", other, img.Name, img.ID)
		}
		ids[img.ID] = img.Name
		images = append(images, img)
	}
	return images, nil
}

func parseSeed(raw []byte, source string) ([]seedImage, error) {
	var f seedFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a misspelt field should fail, not be ignored
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("ims: parsing %s: %w", source, err)
	}
	seen := map[string]bool{}
	for i := range f.Images {
		e := &f.Images[i]
		if err := e.normalise(); err != nil {
			return nil, fmt.Errorf("ims: %s: image %d (%q): %w", source, i+1, e.Name, err)
		}
		if seen[e.Name] {
			return nil, fmt.Errorf("ims: %s: image name %q is repeated", source, e.Name)
		}
		seen[e.Name] = true
	}
	return f.Images, nil
}

// normalise validates an entry and fills its defaults.
func (e *seedImage) normalise() error {
	if e.Name == "" || e.OSVersion == "" || e.Platform == "" {
		return errors.New("name, os_version and platform are required")
	}
	if e.OSType == "" {
		e.OSType = "Linux"
	}
	if e.OSType != "Linux" && e.OSType != "Windows" && e.OSType != "Other" {
		return fmt.Errorf("os_type %q must be Linux, Windows or Other", e.OSType)
	}
	if e.MinDisk == 0 {
		e.MinDisk = 40
	}
	if e.MinDisk < 1 || e.MinDisk > 1024 || e.MinRAM < 0 {
		return errors.New("min_disk must be 1 to 1024 (GB) and min_ram must not be negative")
	}
	if e.Arch == "" {
		e.Arch = "x86"
	}
	if e.Arch != "x86" && e.Arch != "arm" {
		return fmt.Errorf("arch %q must be x86 or arm", e.Arch)
	}
	if e.Firmware == "" {
		e.Firmware = "bios"
	}
	if e.Firmware != "bios" && e.Firmware != "uefi" {
		return fmt.Errorf("firmware %q must be bios or uefi", e.Firmware)
	}
	if e.ID != "" && !uuidRE.MatchString(e.ID) {
		return fmt.Errorf("id %q is not a lowercase UUID", e.ID)
	}
	return nil
}

// mergeSeeds appends extra to base, replacing same-named entries in place.
func mergeSeeds(base, extra []seedImage) []seedImage {
	index := map[string]int{}
	for i, e := range base {
		index[e.Name] = i
	}
	for _, e := range extra {
		if i, ok := index[e.Name]; ok {
			base[i] = e
			continue
		}
		base = append(base, e)
	}
	return base
}

// image builds the public image for a seed entry. position spaces the
// creation times one second apart so that the default sort (newest
// first) is stable and follows the file order.
func (e seedImage) image(position int) Image {
	id := e.ID
	if id == "" {
		id = nameUUID("weistack:ims:public-image:" + e.Name)
	}
	created := Time(seedEpoch.Add(-time.Duration(position) * time.Second))
	img := Image{
		ID:              id,
		Name:            e.Name,
		OSVersion:       e.OSVersion,
		Platform:        e.Platform,
		OSType:          e.OSType,
		OSBit:           "64",
		MinDisk:         e.MinDisk,
		MinRAM:          e.MinRAM,
		HwFirmwareType:  e.Firmware,
		Status:          StatusActive,
		ImageType:       TypeGold,
		Visibility:      VisibilityPublic,
		Owner:           publicOwner,
		Protected:       true,
		IsRegistered:    "true",
		LazyLoading:     "true",
		ImageSourceType: "uds",
		ContainerFormat: "bare",
		DiskFormat:      "zvhd2",
		VirtualEnvType:  "FusionCompute",
		Checksum:        emptyChecksum,
		Tags:            []string{},
		CreatedAt:       created,
		UpdatedAt:       created,
		ActiveAt:        &created,
	}
	if e.Arch == "arm" {
		img.SupportArm = "true"
	}
	img.setLinks()
	return img
}

// setLinks fills the fields derived from the image ID.
func (img *Image) setLinks() {
	img.Schema = "/v2/schemas/image"
	img.Self = "/v2/images/" + img.ID
	img.File = "/v2/images/" + img.ID + "/file"
}

// nameUUID returns the RFC 4122 version 5 UUID of name, so a seeded
// image has the same ID on every machine and after every restart.
func nameUUID(name string) string {
	sum := sha1.Sum([]byte(name)) //nolint:gosec // see import
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
