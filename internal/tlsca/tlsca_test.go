package tlsca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func verify(t *testing.T, a *Authority, host string) *x509.Certificate {
	t.Helper()
	c, err := a.Certificate(host)
	if err != nil {
		t.Fatalf("Certificate(%s): %v", host, err)
	}
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: a.Pool()}); err != nil {
		t.Fatalf("certificate for %s does not verify against the CA: %v", host, err)
	}
	return c.Leaf
}

func TestIssueAndVerify(t *testing.T) {
	t.Parallel()
	a, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"vpc.ap-southeast-1.myhuaweicloud.com", "my-bucket.obs.af-south-1.myhuaweicloud.com", "127.0.0.1"} {
		leaf := verify(t, a, h)
		if leaf.NotAfter.Sub(leaf.NotBefore) > leafValidity+2*time.Hour {
			t.Errorf("%s: validity %s is too long for clients", h, leaf.NotAfter.Sub(leaf.NotBefore))
		}
	}
	// Names are case-insensitive and cached.
	first, _ := a.Certificate("VPC.ap-southeast-1.myhuaweicloud.com.")
	second, _ := a.Certificate("vpc.ap-southeast-1.myhuaweicloud.com")
	if first != second {
		t.Error("the same host was issued two certificates")
	}
	// A certificate for one host does not cover another.
	c, _ := a.Certificate("vpc.ap-southeast-1.myhuaweicloud.com")
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: "ecs.ap-southeast-1.myhuaweicloud.com", Roots: a.Pool()}); err == nil {
		t.Error("a certificate verified for the wrong host")
	}
	if _, err := a.Certificate(""); err == nil {
		t.Error("issued a certificate for no host")
	}
}

func TestExpiredLeafIsReissued(t *testing.T) {
	t.Parallel()
	a, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := a.Certificate("vpc.ap-southeast-1.myhuaweicloud.com")
	a.now = func() time.Time { return time.Now().Add(leafValidity) }
	second, _ := a.Certificate("vpc.ap-southeast-1.myhuaweicloud.com")
	if first == second {
		t.Error("an expiring certificate was not reissued")
	}
}

func TestPersistedCAIsReused(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "nested", "tls")
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("CA key file: %v, mode %v", err, info.Mode())
	}
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.CertPEM()) != string(b.CertPEM()) {
		t.Fatal("reloading the directory created a new CA")
	}
	// A certificate issued by the reloaded CA verifies against the first.
	c, _ := b.Certificate("rds.ap-southeast-1.myhuaweicloud.com")
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: "rds.ap-southeast-1.myhuaweicloud.com", Roots: a.Pool()}); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(a.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CertPEM is not a PEM certificate")
	}
	ca, _ := x509.ParseCertificate(block.Bytes)
	if !ca.IsCA || ca.Subject.CommonName != commonName {
		t.Errorf("CA = %+v", ca.Subject)
	}
}

func TestBrokenCADirectories(t *testing.T) {
	t.Parallel()

	half := t.TempDir()
	if err := os.WriteFile(filepath.Join(half, CertFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(half); err == nil || !strings.Contains(err.Error(), "half") {
		t.Errorf("half a CA: %v", err)
	}

	junk := t.TempDir()
	for _, f := range []string{CertFile, keyFile} {
		if err := os.WriteFile(filepath.Join(junk, f), []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Load(junk); err == nil {
		t.Error("junk CA files were accepted")
	}

	// A leaf certificate where the CA should be.
	a, _ := Load("")
	leaf, _ := a.Certificate("x.example")
	notCA := t.TempDir()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(a.leafKey)
	_ = os.WriteFile(filepath.Join(notCA, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Leaf.Raw}), 0o600)
	_ = os.WriteFile(filepath.Join(notCA, keyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	if _, err := Load(notCA); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("a non-CA certificate: %v", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, nil, 0o600)
	if _, err := Load(filepath.Join(file, "tls")); err == nil {
		t.Error("an unusable directory was accepted")
	}
}

func TestServerConfigUsesSNI(t *testing.T) {
	t.Parallel()
	a, _ := Load("")
	cfg := a.ServerConfig("fallback.myhuaweicloud.com")
	for name, want := range map[string]string{"ims.ap-southeast-1.myhuaweicloud.com": "ims.ap-southeast-1.myhuaweicloud.com", "": "fallback.myhuaweicloud.com"} {
		c, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || c.Leaf.DNSNames[0] != want {
			t.Errorf("SNI %q: %v, %v", name, c, err)
		}
	}
}

func TestConcurrentIssue(t *testing.T) {
	t.Parallel()
	a, _ := Load("")
	var wg sync.WaitGroup
	certs := make([]*tls.Certificate, 20)
	for i := range certs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certs[i], _ = a.Certificate("obs.ap-southeast-1.myhuaweicloud.com")
		}()
	}
	wg.Wait()
	for _, c := range certs {
		if c != certs[0] {
			t.Fatal("concurrent requests for one host got different certificates")
		}
	}
}
