package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/tlsca"
)

func TestCheckCA(t *testing.T) {
	t.Parallel()
	check := func(cfg config.Config, dir string) string {
		t.Helper()
		ca, err := tlsca.Load(dir, cfg.ProxyDomains...)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		checkCA(slog.New(slog.NewTextHandler(&buf, nil)), cfg, ca, dir)
		return buf.String()
	}

	// A new CA covers the proxy domains it was created with.
	dir := t.TempDir()
	if out := check(config.Config{ProxyDomains: []string{"myhuaweicloud.com", "example.test"}}, dir); out != "" {
		t.Errorf("a new CA: %s", out)
	}
	// A proxy domain added later is not covered.
	out := check(config.Config{ProxyDomains: []string{"myhuaweicloud.com", "other.example"}}, dir)
	if !strings.Contains(out, "cannot sign for a proxy domain") || !strings.Contains(out, "other.example") || !strings.Contains(out, "weistack ca") {
		t.Errorf("a domain outside the CA: %s", out)
	}

	// A CA from before v0.3 has no constraints.
	old := t.TempDir()
	writeUnconstrainedCA(t, old)
	if out := check(config.Config{ProxyDomains: []string{"myhuaweicloud.com"}}, old); !strings.Contains(out, "before v0.3") {
		t.Errorf("an unconstrained CA: %s", out)
	}
}

func writeUnconstrainedCA(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "WeiStack local CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
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
	for name, block := range map[string]*pem.Block{
		tlsca.CertFile: {Type: "CERTIFICATE", Bytes: der},
		tlsca.KeyFile:  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
