package sdk

import (
	"crypto/rand"
	"os"
)

// The suite runs in either IAM mode. In accept mode (the default) any
// credentials work, and tests use made-up access keys of their own. With
// WEISTACK_SDK_IAM=enforce the emulator checks every signature, so tests
// sign with the administrator's key pair, which the suite generates and
// gives the emulator, or reads from WEISTACK_SDK_AK and WEISTACK_SDK_SK
// for an emulator started elsewhere.
var (
	enforcing = os.Getenv("WEISTACK_SDK_IAM") == "enforce"
	adminAK   = envOr("WEISTACK_SDK_AK", "SDKADMIN"+rand.Text()[:12])
	adminSK   = envOr("WEISTACK_SDK_SK", rand.Text()+rand.Text()[:14])
)

// fakeSecret is the secret key tests send in accept mode, where none is
// checked.
const fakeSecret = "weistack-does-not-verify-signatures"

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// signingAK returns the access key a test signs with: its own in accept
// mode, the administrator's when credentials are enforced.
func signingAK(own string) string {
	if enforcing {
		return adminAK
	}
	return own
}

// signingSK returns the matching secret key.
func signingSK() string {
	if enforcing {
		return adminSK
	}
	return fakeSecret
}

// emulatorIAMEnv is the environment that sets the emulator's IAM mode.
func emulatorIAMEnv() []string {
	if !enforcing {
		return nil
	}
	return []string{"WEISTACK_IAM=enforce", "WEISTACK_ADMIN_ACCESS_KEY=" + adminAK, "WEISTACK_ADMIN_SECRET_KEY=" + adminSK}
}
