package kms

import (
	"net/http"
)

// Key rotation (api-dew "Key Rotation Management"): a symmetric key KMS
// made, other than a default key, gets new material every
// rotation_interval days (30 to 365, 365 by default). Older material
// still decrypts what it encrypted. WeiStack rotates when a key with
// rotation enabled is next used after its interval.

// emptyObject answers 200 with {}: the API pages list no response
// fields for the rotation operations, and Terraform's client decodes a
// JSON body.
func emptyObject(w http.ResponseWriter) error { return write(w, struct{}{}) }

// rotatable checks a key can be rotated.
func rotatable(k key) error {
	switch {
	case k.Default:
		return errDefaultKey
	case specs[k.Spec] == asymmetric:
		return errAsymmetricOp
	case specs[k.Spec] != symmetric, k.Origin != "kms":
		return errParam
	}
	return nil
}

func (s *Service) handleEnableRotation(w http.ResponseWriter, r *http.Request, t tenant, k key) error {
	_, err := s.update(r.Context(), t, k.ID, func(k *key) error {
		if err := rotatable(*k); err != nil {
			return err
		}
		if err := usable(*k); err != nil {
			return err
		}
		if k.Rotation {
			return errRotationOn
		}
		k.Rotation = true
		if k.LastRotation.IsZero() {
			// The interval counts from when rotation is turned on.
			k.LastRotation = s.now().UTC()
		}
		return nil
	})
	if err != nil {
		return err
	}
	return emptyObject(w)
}

func (s *Service) handleDisableRotation(w http.ResponseWriter, r *http.Request, t tenant, k key) error {
	_, err := s.update(r.Context(), t, k.ID, func(k *key) error {
		if err := rotatable(*k); err != nil {
			return err
		}
		if !k.Rotation {
			return errRotationOff
		}
		k.Rotation = false
		return nil
	})
	if err != nil {
		return err
	}
	return emptyObject(w)
}

func (s *Service) handleRotationInterval(w http.ResponseWriter, r *http.Request, t tenant) error {
	var b rotationIntervalRequest
	if err := decode(r, &b); err != nil {
		return err
	}
	if _, err := s.authorized(r, t, "kms:cmk:updateRotation", b.KeyID); err != nil {
		return err
	}
	switch {
	case !b.RotationInterval.set:
		return errMissing
	case b.RotationInterval.bad || b.RotationInterval.v < minRotationDays || b.RotationInterval.v > maxRotationDays:
		return errInterval
	}
	_, err := s.update(r.Context(), t, b.KeyID, func(k *key) error {
		if err := rotatable(*k); err != nil {
			return err
		}
		if !k.Rotation {
			return errRotationOff
		}
		k.RotationInterval = b.RotationInterval.v
		return nil
	})
	if err != nil {
		return err
	}
	return emptyObject(w)
}

func (s *Service) handleRotationStatus(w http.ResponseWriter, _ *http.Request, _ tenant, k key) error {
	return write(w, rotationStatus{
		KeyRotationEnabled: k.Rotation, RotationInterval: k.RotationInterval,
		LastRotationTime: millis(k.LastRotation), NumberOfRotations: len(k.Materials) - 1,
	})
}
