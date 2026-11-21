package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

// The data format.
//
// A database records the version of the format it was written in, so a
// release can tell whether it can read a file, and upgrade it if it is
// older. The version changes only when a release changes how something
// already stored is laid out; adding a new kind of resource does not
// change it.
//
// Files written by v0.1 releases carry no version: they are format 1.

// FormatVersion is the format this release writes.
const FormatVersion = 2

// ErrNewerFormat reports a database written by a newer WeiStack.
var ErrNewerFormat = errors.New("store: database written by a newer WeiStack")

// metaBucket holds the database's own metadata. Scope names always
// contain "/", so it cannot collide with stored resources.
const metaBucket = "_weistack"

var formatKey = []byte("format")

// migration upgrades a database from one format to the next inside one
// transaction.
type migration func(tx *bolt.Tx) error

// migrations[n] upgrades format n to n+1.
var migrations = map[uint64]migration{
	1: migrateFormat1To2,
}

// format1Disk, format1Server, format2Volume and format2Attachment
// describe data formats 1 and 2 and must never change.
type format1Disk struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	SizeGB   int    `json:"size"`
	Device   string `json:"device"`
	KMSKeyID string `json:"kms_key_id"`
}

type format1Server struct {
	ID                  string        `json:"id"`
	Name                string        `json:"name"`
	AvailabilityZone    string        `json:"availability_zone"`
	EnterpriseProjectID string        `json:"enterprise_project_id"`
	ImageID             string        `json:"image_id"`
	ImageName           string        `json:"image_name"`
	Created             string        `json:"created"`
	Updated             string        `json:"updated"`
	RootVolume          format1Disk   `json:"root_volume"`
	DataVolumes         []format1Disk `json:"data_volumes"`
}

type format2Attachment struct {
	ID                  string `json:"id"`
	ServerID            string `json:"server_id"`
	Device              string `json:"device"`
	BootIndex           int    `json:"boot_index"`
	DeleteOnTermination bool   `json:"delete_on_termination"`
	AttachedAt          string `json:"attached_at"`
}

type format2Volume struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Description         string              `json:"description"`
	Status              string              `json:"status"`
	SizeGB              int                 `json:"size"`
	VolumeType          string              `json:"volume_type"`
	AvailabilityZone    string              `json:"availability_zone"`
	Bootable            bool                `json:"bootable"`
	ImageID             string              `json:"image_id,omitempty"`
	ImageName           string              `json:"image_name,omitempty"`
	SnapshotID          string              `json:"snapshot_id,omitempty"`
	KMSKeyID            string              `json:"kms_key_id,omitempty"`
	Passthrough         bool                `json:"passthrough,omitempty"`
	Multiattach         bool                `json:"multiattach,omitempty"`
	IOPS                int                 `json:"iops,omitempty"`
	Throughput          int                 `json:"throughput,omitempty"`
	QoSID               string              `json:"qos_id,omitempty"`
	Metadata            map[string]string   `json:"metadata,omitempty"`
	Tags                map[string]string   `json:"tags,omitempty"`
	EnterpriseProjectID string              `json:"enterprise_project_id"`
	Attachments         []format2Attachment `json:"attachments"`
	CreatedAt           string              `json:"created_at"`
	UpdatedAt           string              `json:"updated_at"`
}

func migrateFormat1To2(tx *bolt.Tx) error {
	var serverBuckets []struct {
		key   string
		scope Scope
	}
	_ = tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		key := string(name)
		if key == metaBucket {
			return nil
		}
		sc, err := ParseScope(key)
		if err != nil || sc.Kind != "ecs.server" {
			return nil
		}
		serverBuckets = append(serverBuckets, struct {
			key   string
			scope Scope
		}{key: key, scope: sc})
		return nil
	})

	for _, sb := range serverBuckets {
		bkt := tx.Bucket([]byte(sb.key))
		if bkt == nil {
			continue
		}
		volKey, err := (Scope{Region: sb.scope.Region, ProjectID: sb.scope.ProjectID, Kind: "evs.volume"}).key()
		if err != nil {
			return err
		}
		volBkt, err := tx.CreateBucketIfNotExists([]byte(volKey))
		if err != nil {
			return err
		}

		type rewrite struct {
			k   []byte
			val []byte
		}
		var updates []rewrite
		err = bkt.ForEach(func(k, v []byte) error {
			if len(v) < boltHeaderLen {
				return fmt.Errorf("store: corrupt server record %s/%s", sb.key, k)
			}
			seq := binary.BigEndian.Uint64(v[0:8])
			ver := binary.BigEndian.Uint64(v[8:16])
			payload := v[boltHeaderLen:]

			var srv format1Server
			if err := json.Unmarshal(payload, &srv); err != nil {
				return fmt.Errorf("store: decoding server %s/%s: %w", sb.key, k, err)
			}

			disks := make([]format1Disk, 0, 1+len(srv.DataVolumes))
			disks = append(disks, srv.RootVolume)
			disks = append(disks, srv.DataVolumes...)
			for idx, d := range disks {
				if d.ID == "" {
					continue
				}
				bootIndex := -1
				var imgID, imgName string
				if idx == 0 {
					bootIndex = 0
					imgID, imgName = srv.ImageID, srv.ImageName
				}
				vol := format2Volume{
					ID:                  d.ID,
					Name:                fmt.Sprintf("%s-volume-%04d", srv.Name, idx),
					Status:              "in-use",
					SizeGB:              d.SizeGB,
					VolumeType:          d.Type,
					AvailabilityZone:    srv.AvailabilityZone,
					Bootable:            idx == 0,
					ImageID:             imgID,
					ImageName:           imgName,
					KMSKeyID:            d.KMSKeyID,
					EnterpriseProjectID: srv.EnterpriseProjectID,
					Attachments: []format2Attachment{{
						ID:                  d.ID,
						ServerID:            srv.ID,
						Device:              d.Device,
						BootIndex:           bootIndex,
						DeleteOnTermination: true,
						AttachedAt:          srv.Created,
					}},
					CreatedAt: srv.Created,
					UpdatedAt: srv.Updated,
				}
				volBytes, err := json.Marshal(vol)
				if err != nil {
					return err
				}
				volSeq, err := volBkt.NextSequence()
				if err != nil {
					return err
				}
				if err := volBkt.Put([]byte(d.ID), encodeBolt(volSeq, 1, volBytes)); err != nil {
					return err
				}
			}

			var raw map[string]json.RawMessage
			if err := json.Unmarshal(payload, &raw); err != nil {
				return err
			}
			delete(raw, "root_volume")
			delete(raw, "data_volumes")
			cleaned, err := json.Marshal(raw)
			if err != nil {
				return err
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			updates = append(updates, rewrite{k: keyCopy, val: encodeBolt(seq, ver+1, cleaned)})
			return nil
		})
		if err != nil {
			return err
		}
		for _, u := range updates {
			if err := bkt.Put(u.k, u.val); err != nil {
				return err
			}
		}
	}
	return nil
}

// prepareFormat records or checks the format of an open database, backs
// it up and migrates it when it is older than current.
func prepareFormat(db *bolt.DB, path string, current uint64, steps map[uint64]migration) error {
	// Read first, in a read-only transaction: a file this release refuses
	// must be left exactly as it was.
	var found uint64
	recorded := false
	err := db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return nil
		}
		recorded = true
		v, err := readFormat(meta)
		found = v
		return err
	})
	if err != nil {
		return err
	}
	if !recorded {
		// No metadata: either a new file or one written by v0.1.
		err := db.Update(func(tx *bolt.Tx) error {
			found = current
			if hasScopes(tx) {
				found = 1
			}
			return writeFormat(tx, found)
		})
		if err != nil {
			return err
		}
	}

	switch {
	case found > current:
		return fmt.Errorf("%w: %s is format %d, and this release reads up to format %d; use that release or a newer one",
			ErrNewerFormat, path, found, current)
	case found == current:
		return nil
	}

	backup := fmt.Sprintf("%s.format%d.bak", path, found)
	if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
		if err := db.View(func(tx *bolt.Tx) error { return tx.CopyFile(backup, 0o600) }); err != nil {
			return fmt.Errorf("store: backing up %s before upgrading it: %w", path, err)
		}
	}
	for v := found; v < current; v++ {
		step, ok := steps[v]
		if !ok {
			return fmt.Errorf("store: no upgrade from format %d to %d", v, v+1)
		}
		err := db.Update(func(tx *bolt.Tx) error {
			if err := step(tx); err != nil {
				return err
			}
			return writeFormat(tx, v+1)
		})
		if err != nil {
			return fmt.Errorf("store: upgrading %s from format %d to %d (the original is in %s): %w", path, v, v+1, backup, err)
		}
	}
	return nil
}

func hasScopes(tx *bolt.Tx) bool {
	found := false
	_ = tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		if string(name) != metaBucket {
			found = true
		}
		return nil
	})
	return found
}

// The version is stored like any record, a 16-byte header then JSON, so
// a v0.1 binary that opens the file shows it as one more record instead
// of failing on an unexpected value.
func writeFormat(tx *bolt.Tx, v uint64) error {
	meta, err := tx.CreateBucketIfNotExists([]byte(metaBucket))
	if err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return meta.Put(formatKey, encodeBolt(1, v, data))
}

func readFormat(meta *bolt.Bucket) (uint64, error) {
	raw := meta.Get(formatKey)
	if len(raw) < boltHeaderLen {
		return 0, errors.New("store: the database's format record is missing or corrupt")
	}
	var v uint64
	if err := json.Unmarshal(raw[boltHeaderLen:], &v); err != nil || v == 0 {
		return 0, fmt.Errorf("store: the database's format record is corrupt: %q", raw[boltHeaderLen:])
	}
	return v, nil
}

// Format returns the format version recorded in the database.
func (b *Bolt) Format() (uint64, error) {
	var v uint64
	err := b.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return errors.New("store: the database records no format")
		}
		var err error
		v, err = readFormat(meta)
		return err
	})
	return v, err
}
