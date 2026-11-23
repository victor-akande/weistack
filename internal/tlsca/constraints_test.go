package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCAIsConstrained(t *testing.T) {
	t.Parallel()
	a, err := Load(t.TempDir(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Constrained() || !a.cert.PermittedDNSDomainsCritical {
		t.Fatalf("constrained %v, critical %v", a.Constrained(), a.cert.PermittedDNSDomainsCritical)
	}
	for _, h := range []string{
		"vpc.ap-southeast-1.myhuaweicloud.com", "myhuaweicloud.com", "api.example.test",
		"localhost", "ecs.localhost", "mypc.local", "nas.home.arpa", "box.lan", "svc.internal",
		"127.0.0.1", "192.168.1.5", "10.0.0.1", "172.16.4.4", "100.64.1.1", "::1", "fd12::1",
	} {
		if !a.Permits(h) {
			t.Errorf("Permits(%s) = false", h)
		}
		verify(t, a, h)
	}
	for _, h := range []string{"example.com", "myhuaweicloud.com.evil.example", "evilmyhuaweicloud.com", "victor-pc", "8.8.8.8", "2001:db8::1"} {
		if a.Permits(h) {
			t.Errorf("Permits(%s) = true", h)
		}
		if _, err := a.Certificate(h); err == nil {
			t.Errorf("issued a certificate for %s", h)
		}
	}
}

// TestConstraintsBindClients: even a certificate signed with the CA's
// key, outside the issuing code, is refused by clients for other names.
func TestConstraintsBindClients(t *testing.T) {
	t.Parallel()
	a, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dns string
		ip  string
	}{{dns: "bank.example"}, {ip: "8.8.8.8"}} {
		tmpl := &x509.Certificate{
			SerialNumber: mustSerial(t), Subject: pkix.Name{CommonName: tc.dns + tc.ip},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if tc.dns != "" {
			tmpl.DNSNames = []string{tc.dns}
		} else {
			tmpl.IPAddresses = append(tmpl.IPAddresses, parseIP(t, tc.ip))
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: tc.dns + tc.ip, Roots: a.Pool()}); err == nil {
			t.Errorf("a certificate for %s%s verified", tc.dns, tc.ip)
		}
	}
}

// TestUnconstrainedCAStillWorks: a CA created before v0.3 is loaded as
// it is, reported as unconstrained, and still signs for any name.
func TestUnconstrainedCAStillWorks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(t), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, typ string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(KeyFile, "PRIVATE KEY", keyDER)
	write(CertFile, "CERTIFICATE", der)

	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Constrained() || !a.Permits("example.com") {
		t.Fatalf("constrained %v", a.Constrained())
	}
	verify(t, a, "example.com")
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := serial()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("not an IP: %s", s)
	}
	return ip
}
