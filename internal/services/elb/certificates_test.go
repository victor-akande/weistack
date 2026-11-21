package elb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/victor-akande/weistack/internal/core/apierr"
	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/core/ids"
	"github.com/victor-akande/weistack/internal/core/lifecycle"
	"github.com/victor-akande/weistack/internal/core/pagination"
	"github.com/victor-akande/weistack/internal/core/store"
	"github.com/victor-akande/weistack/internal/core/vault"
	"github.com/victor-akande/weistack/internal/server"
	"github.com/victor-akande/weistack/internal/services/eip"
	"github.com/victor-akande/weistack/internal/services/vpc"
	"github.com/victor-akande/weistack/internal/testutil/golden"
)

const (
	certTestProject  = "0123456789abcdef0123456789abcdef"
	certTestProjectB = "fedcba9876543210fedcba9876543210"
	certTestRegion   = "ap-southeast-1"
	certTestHost     = "elb." + certTestRegion + ".myhuaweicloud.com"
	certUnknownUUID  = "00000000-0000-4000-8000-000000000000"
	certCustomEP     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var (
	certTestTenant  = Tenant{Region: certTestRegion, ProjectID: certTestProject}
	certTestTenantB = Tenant{Region: certTestRegion, ProjectID: certTestProjectB}
	certTestEpoch   = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
)

type certStubNetwork struct{}

func (certStubNetwork) GetVPC(context.Context, vpc.Tenant, string) (vpc.VPC, error) {
	return vpc.VPC{}, errors.New("unexpected GetVPC")
}
func (certStubNetwork) GetSubnet(context.Context, vpc.Tenant, string) (vpc.Subnet, error) {
	return vpc.Subnet{}, errors.New("unexpected GetSubnet")
}
func (certStubNetwork) ListSubnets(context.Context, vpc.Tenant, vpc.ListSubnetsFilter) ([]vpc.Subnet, error) {
	return nil, nil
}
func (certStubNetwork) AllocateIP(context.Context, vpc.Tenant, string, string, string) (string, error) {
	return "", errors.New("unexpected AllocateIP")
}
func (certStubNetwork) ReleaseIP(context.Context, vpc.Tenant, string, string) error {
	return nil
}

type certStubPublicIPs struct{}

func (certStubPublicIPs) BindToELB(context.Context, vpc.Tenant, string, string, string, string) (string, error) {
	return "", errors.New("unexpected BindToELB")
}
func (certStubPublicIPs) CreateForELB(context.Context, vpc.Tenant, string, string, string, eip.ServerIP) (string, string, error) {
	return "", "", errors.New("unexpected CreateForELB")
}
func (certStubPublicIPs) UnbindFromELB(context.Context, vpc.Tenant, string, string) error {
	return nil
}
func (certStubPublicIPs) PublicIPAddress(context.Context, vpc.Tenant, string) (string, bool, error) {
	return "", false, nil
}

type certStubServers struct{}

func (certStubServers) ServerAt(context.Context, vpc.Tenant, string, string, string) (string, bool, error) {
	return "", false, nil
}

type certEnv struct {
	svc     *Service
	store   store.Store
	vault   *vault.Vault
	clock   *lifecycle.FakeClock
	handler http.Handler
	lbID    string
}

func certNewEnv(t *testing.T) *certEnv {
	t.Helper()
	st := store.NewMemory()
	t.Cleanup(func() { _ = st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := lifecycle.NewFakeClock(certTestEpoch)
	gen := ids.NewSeeded(55)

	vltKey := make([]byte, vault.KeyLen)
	for i := range vltKey {
		vltKey[i] = byte(i + 10)
	}
	vlt, err := vault.New(vltKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	svc, err := New(Deps{
		Store:   st,
		IDs:     gen,
		Logger:  log,
		Vault:   vlt,
		VPC:     certStubNetwork{},
		EIPs:    certStubPublicIPs{},
		Servers: certStubServers{},
		Now:     clock.Now,
	})
	if err != nil {
		t.Fatalf("elb.New: %v", err)
	}

	cfg, err := config.Load(nil, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	engine := lifecycle.New(lifecycle.Options{Clock: clock, Logger: log})
	srv, err := server.New(server.Options{
		Config:    cfg,
		ProjectID: certTestProject,
		Logger:    log,
		Store:     st,
		Engine:    engine,
		IDs:       gen,
		Services:  []server.Service{svc},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	e := &certEnv{
		svc:     svc,
		store:   st,
		vault:   vlt,
		clock:   clock,
		handler: srv.Handler(),
	}
	e.lbID = e.seedLB(t, certTestTenant, "cert-test-lb")
	return e
}

func (e *certEnv) seedLB(t *testing.T, tenant Tenant, name string) string {
	t.Helper()
	id := e.svc.ids.UUID()
	lb := loadBalancer{
		ID:                  id,
		Name:                name,
		AdminStateUp:        true,
		L4FlavorID:          "l4-flv",
		L7FlavorID:          "l7-flv",
		EnterpriseProjectID: defaultEnterpriseProjectID,
		CreatedAt:           certTestEpoch,
		UpdatedAt:           certTestEpoch,
	}
	if err := e.svc.loadBalancers(tenant).Create(t.Context(), id, lb); err != nil {
		t.Fatalf("seedLB %s: %v", name, err)
	}
	return id
}

func (e *certEnv) call(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	return e.callAs(t, certTestProject, method, path, body)
}

func (e *certEnv) callAs(t *testing.T, project, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/v3/"+project+"/elb"+path, rd)
	r.Host = certTestHost
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return res.StatusCode, out
}

func (e *certEnv) expect(t *testing.T, goldenName, method, path, body string) []byte {
	t.Helper()
	status, out := e.call(t, method, path, body)
	golden.Assert(t, filepath.Join("testdata", "certificates", goldenName+".json"), status, out)
	return out
}

func certPtr[T any](v T) *T { return &v }

func certDecodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	return v
}

func certCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return err.Error()
}

type certGenerated struct {
	certPEM     string
	keyPKCS1PEM string
	keySEC1PEM  string
	keyPKCS8PEM string
	fingerprint string
	key         crypto.Signer
}

func certGenRSA(t *testing.T, cn string, dnsSANs []string, ipSANs []net.IP, isCA bool, notAfter time.Time) certGenerated {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             certTestEpoch.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              dnsSANs,
		IPAddresses:           ipSANs,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	sum := sha1.Sum(der)
	return certGenerated{
		certPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPKCS1PEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		keyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})),
		fingerprint: fmt.Sprintf("%x", sum),
		key:         key,
	}
}

func certGenECDSA(t *testing.T, cn string, dnsSANs []string, isCA bool, notAfter time.Time) certGenerated {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             certTestEpoch.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              dnsSANs,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	sec1Bytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	sum := sha1.Sum(der)
	return certGenerated{
		certPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keySEC1PEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1Bytes})),
		keyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})),
		fingerprint: fmt.Sprintf("%x", sum),
		key:         key,
	}
}

// certGenChain builds a real ECDSA certificate chain of depth certificates (leaf first, root CA last).
func certGenChain(t *testing.T, cn string, dnsSANs []string, depth int, notAfter time.Time) certGenerated {
	t.Helper()
	if depth < 1 {
		t.Fatalf("depth must be >= 1")
	}
	keys := make([]*ecdsa.PrivateKey, depth)
	certs := make([]*x509.Certificate, depth)
	ders := make([][]byte, depth)

	// Build from root (index depth-1) down to leaf (index 0).
	for i := depth - 1; i >= 0; i-- {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		keys[i] = k
		isLeaf := i == 0
		subjectCN := cn
		var sans []string
		if isLeaf {
			sans = dnsSANs
		} else {
			subjectCN = fmt.Sprintf("Intermediate-CA-%d", i)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(100 + i)),
			Subject:               pkix.Name{CommonName: subjectCN},
			NotBefore:             certTestEpoch.Add(-time.Hour),
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  !isLeaf,
			DNSNames:              sans,
		}
		if !isLeaf {
			tmpl.KeyUsage |= x509.KeyUsageCertSign
		}
		parentCert := tmpl
		parentKey := k
		if i < depth-1 {
			parentCert = certs[i+1]
			parentKey = keys[i+1]
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &k.PublicKey, parentKey)
		if err != nil {
			t.Fatalf("x509.CreateCertificate depth %d: %v", i, err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("x509.ParseCertificate depth %d: %v", i, err)
		}
		ders[i] = der
		certs[i] = parsed
	}

	var chainBuf bytes.Buffer
	for i := range depth {
		chainBuf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ders[i]}))
	}
	sec1, err := x509.MarshalECPrivateKey(keys[0])
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(keys[0])
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	sum := sha1.Sum(ders[0])
	return certGenerated{
		certPEM:     chainBuf.String(),
		keySEC1PEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})),
		keyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		fingerprint: fmt.Sprintf("%x", sum),
		key:         keys[0],
	}
}

// certGenWithExistingKey issues a new leaf certificate using an existing signer's key pair.
func certGenWithExistingKey(t *testing.T, key crypto.Signer, cn string, dnsSANs []string, notAfter time.Time) (string, string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(999),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             certTestEpoch.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              dnsSANs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	sum := sha1.Sum(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), fmt.Sprintf("%x", sum)
}

func certKeyBodySnippet(keyPEM string) string {
	lines := strings.Split(strings.TrimSpace(keyPEM), "\n")
	if len(lines) >= 3 {
		return lines[1]
	}
	return keyPEM
}

func certAssertNoPlaintextKeyInStore(t *testing.T, st store.Store, keyPEMs ...string) {
	t.Helper()
	dump, err := st.Dump(t.Context())
	if err != nil {
		t.Fatalf("store.Dump: %v", err)
	}
	for scope, recs := range dump {
		for _, rec := range recs {
			raw := string(rec.Data)
			for _, keyPEM := range keyPEMs {
				if keyPEM == "" {
					continue
				}
				snippet := certKeyBodySnippet(keyPEM)
				if strings.Contains(raw, keyPEM) || strings.Contains(raw, snippet) || strings.Contains(raw, "PRIVATE KEY") {
					t.Fatalf("plaintext private key leaked into store scope %s record %s", scope, rec.ID)
				}
			}
		}
	}
}

func TestCertCreateValidation(t *testing.T) {
	t.Parallel()

	notAfter := certTestEpoch.AddDate(1, 0, 0)
	rsaGood := certGenRSA(t, "rsa.example.com", []string{"rsa.example.com", "alt.example.com"}, []net.IP{net.ParseIP("192.0.2.10")}, false, notAfter)
	rsaOther := certGenRSA(t, "other.example.com", nil, nil, false, notAfter)
	ecGood := certGenECDSA(t, "ec.example.com", []string{"ec.example.com"}, false, notAfter)
	chain3 := certGenChain(t, "chain.example.com", []string{"chain.example.com"}, 3, notAfter)
	chain11 := certGenChain(t, "chain11.example.com", nil, 11, notAfter)
	chain12 := certGenChain(t, "chain12.example.com", nil, 12, notAfter)
	caGood := certGenECDSA(t, "Root CA", nil, true, notAfter)

	tooManyDomains := strings.Repeat("a.example.com,", 101)
	tooManyDomains = strings.TrimSuffix(tooManyDomains, ",")
	tooLongDomain := strings.Repeat("a.example.com,", 800)
	tooLongDomain = strings.TrimSuffix(tooLongDomain, ",")

	tests := []struct {
		name     string
		in       certCreateInput
		wantCode string
		check    func(t *testing.T, got certificate)
	}{
		{
			name: "good RSA PKCS#1 with default type and IP SANs",
			in: certCreateInput{
				Name:        "rsa-pkcs1",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			check: func(t *testing.T, got certificate) {
				if got.Type != certTypeServer {
					t.Errorf("Type = %q, want server", got.Type)
				}
				if got.CommonName != "rsa.example.com" || got.Domain != "rsa.example.com" {
					t.Errorf("CN=%q Domain=%q, want rsa.example.com", got.CommonName, got.Domain)
				}
				if got.Fingerprint != rsaGood.fingerprint || len(got.Fingerprint) != 40 {
					t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, rsaGood.fingerprint)
				}
				wantSANs := []string{"rsa.example.com", "alt.example.com", "192.0.2.10"}
				if !slices.Equal(got.SubjectAlternativeNames, wantSANs) {
					t.Errorf("SANs = %v, want %v", got.SubjectAlternativeNames, wantSANs)
				}
				if !got.ExpireTime.Equal(notAfter) {
					t.Errorf("ExpireTime = %v, want %v", got.ExpireTime, notAfter)
				}
				if len(got.SealedPrivateKey) == 0 {
					t.Errorf("expected sealed private key")
				}
			},
		},
		{
			name: "good RSA PKCS#8 with explicit wildcard domain",
			in: certCreateInput{
				Name:        "rsa-pkcs8",
				Type:        "server",
				Domain:      "www.example.com,*.api.example.com",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS8PEM,
			},
			check: func(t *testing.T, got certificate) {
				if got.Domain != "www.example.com,*.api.example.com" {
					t.Errorf("Domain = %q", got.Domain)
				}
			},
		},
		{
			name: "good ECDSA SEC 1 pair",
			in: certCreateInput{
				Name:        "ec-sec1",
				Type:        "server",
				Certificate: ecGood.certPEM,
				PrivateKey:  ecGood.keySEC1PEM,
			},
			check: func(t *testing.T, got certificate) {
				if got.Fingerprint != ecGood.fingerprint {
					t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, ecGood.fingerprint)
				}
			},
		},
		{
			name: "good ECDSA PKCS#8 pair",
			in: certCreateInput{
				Name:        "ec-pkcs8",
				Type:        "server",
				Certificate: ecGood.certPEM,
				PrivateKey:  ecGood.keyPKCS8PEM,
			},
		},
		{
			name: "good 3-cert chain derives leaf fields",
			in: certCreateInput{
				Name:        "chain-3",
				Type:        "server",
				Certificate: chain3.certPEM,
				PrivateKey:  chain3.keySEC1PEM,
			},
			check: func(t *testing.T, got certificate) {
				if got.CommonName != "chain.example.com" || got.Fingerprint != chain3.fingerprint {
					t.Errorf("chain leaf mismatch: CN=%q fp=%q", got.CommonName, got.Fingerprint)
				}
			},
		},
		{
			name: "11-cert chain allowed",
			in: certCreateInput{
				Name:        "chain-11",
				Type:        "server",
				Certificate: chain11.certPEM,
				PrivateKey:  chain11.keySEC1PEM,
			},
		},
		{
			name: "12-cert chain rejected",
			in: certCreateInput{
				Name:        "chain-12",
				Type:        "server",
				Certificate: chain12.certPEM,
				PrivateKey:  chain12.keySEC1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "mismatched key",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaOther.keyPKCS1PEM,
			},
			wantCode: "ELB.1011",
		},
		{
			name: "mismatched RSA cert with ECDSA key",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  ecGood.keySEC1PEM,
			},
			wantCode: "ELB.1011",
		},
		{
			name: "bad server cert PEM",
			in: certCreateInput{
				Type:        "server",
				Certificate: "not a pem certificate",
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.1011",
		},
		{
			name: "trailing garbage after server cert PEM",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM + "\njunk",
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.1011",
		},
		{
			name: "bad private key PEM",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  "not a pem key",
			},
			wantCode: "ELB.1011",
		},
		{
			name: "certificate pasted into private_key",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.certPEM,
			},
			wantCode: "ELB.1011",
		},
		{
			name: "missing server certificate",
			in: certCreateInput{
				Type:       "server",
				PrivateKey: rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "missing server private key",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "oversized server certificate",
			in: certCreateInput{
				Type:        "server",
				Certificate: strings.Repeat("a", certMaxCertLen+1),
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "oversized server private key",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  strings.Repeat("a", certMaxKeyLen+1),
			},
			wantCode: "ELB.8902",
		},
		{
			name: "CA as client succeeds and ignores private_key",
			in: certCreateInput{
				Name:        "ca-good",
				Type:        "client",
				Certificate: caGood.certPEM,
				PrivateKey:  "ignored-secret-material",
			},
			check: func(t *testing.T, got certificate) {
				if got.Type != certTypeClient {
					t.Errorf("Type = %q, want client", got.Type)
				}
				if got.SealedPrivateKey != nil {
					t.Errorf("expected nil SealedPrivateKey for client cert")
				}
				if got.CommonName != "Root CA" {
					t.Errorf("CommonName = %q, want Root CA", got.CommonName)
				}
			},
		},
		{
			name: "non-CA as client rejected with ELB.5051",
			in: certCreateInput{
				Type:        "client",
				Certificate: rsaGood.certPEM,
			},
			wantCode: "ELB.5051",
		},
		{
			name: "bad client PEM rejected with ELB.5051",
			in: certCreateInput{
				Type:        "client",
				Certificate: "not a valid CA PEM",
			},
			wantCode: "ELB.5051",
		},
		{
			name: "missing client certificate rejected with ELB.8902",
			in: certCreateInput{
				Type: "client",
			},
			wantCode: "ELB.8902",
		},
		{
			name: "server_sm returns 501",
			in: certCreateInput{
				Type:        "server_sm",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "WeiStack.0501",
		},
		{
			name: "enc_certificate returns 501",
			in: certCreateInput{
				Type:           "server",
				Certificate:    rsaGood.certPEM,
				PrivateKey:     rsaGood.keyPKCS1PEM,
				EncCertificate: rsaGood.certPEM,
			},
			wantCode: "WeiStack.0501",
		},
		{
			name: "enc_private_key returns 501",
			in: certCreateInput{
				Type:          "server",
				Certificate:   rsaGood.certPEM,
				PrivateKey:    rsaGood.keyPKCS1PEM,
				EncPrivateKey: rsaGood.keyPKCS1PEM,
			},
			wantCode: "WeiStack.0501",
		},
		{
			name: "scm_certificate_id returns 501",
			in: certCreateInput{
				Type:             "server",
				Certificate:      rsaGood.certPEM,
				PrivateKey:       rsaGood.keyPKCS1PEM,
				ScmCertificateID: "scm-12345",
			},
			wantCode: "WeiStack.0501",
		},
		{
			name: "source scm returns 501",
			in: certCreateInput{
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
				Source:      "scm",
			},
			wantCode: "WeiStack.0501",
		},
		{
			name: "unknown type rejected",
			in: certCreateInput{
				Type:        "unknown",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid domain leading hyphen",
			in: certCreateInput{
				Type:        "server",
				Domain:      "-bad.example.com",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid domain malformed wildcard",
			in: certCreateInput{
				Type:        "server",
				Domain:      "*bad.example.com",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid domain single label",
			in: certCreateInput{
				Type:        "server",
				Domain:      "localhost",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid domain over 100 entries",
			in: certCreateInput{
				Type:        "server",
				Domain:      tooManyDomains,
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid domain over 10000 chars",
			in: certCreateInput{
				Type:        "server",
				Domain:      tooLongDomain,
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid enterprise_project_id empty",
			in: certCreateInput{
				Type:                "server",
				Certificate:         rsaGood.certPEM,
				PrivateKey:          rsaGood.keyPKCS1PEM,
				EnterpriseProjectID: certPtr(""),
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid protection_status",
			in: certCreateInput{
				Type:             "server",
				Certificate:      rsaGood.certPEM,
				PrivateKey:       rsaGood.keyPKCS1PEM,
				ProtectionStatus: "invalid",
			},
			wantCode: "ELB.8902",
		},
		{
			name: "invalid protection_reason with angle brackets",
			in: certCreateInput{
				Type:             "server",
				Certificate:      rsaGood.certPEM,
				PrivateKey:       rsaGood.keyPKCS1PEM,
				ProtectionReason: "<bad>",
			},
			wantCode: "ELB.8902",
		},
		{
			name: "name over 255 chars",
			in: certCreateInput{
				Name:        strings.Repeat("x", 256),
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
		{
			name: "description over 255 chars",
			in: certCreateInput{
				Description: strings.Repeat("d", 256),
				Type:        "server",
				Certificate: rsaGood.certPEM,
				PrivateKey:  rsaGood.keyPKCS1PEM,
			},
			wantCode: "ELB.8902",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := certNewEnv(t)
			got, err := e.svc.certCreate(t.Context(), certTestTenant, tc.in)
			if tc.wantCode != "" {
				if code := certCodeOf(err); code != tc.wantCode {
					t.Fatalf("err = %v (code %q), want code %q", err, code, tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestCertPrivateKeySealingAndSecrecy(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	notAfter := certTestEpoch.AddDate(1, 0, 0)
	rsaPair := certGenRSA(t, "secret.example.com", []string{"secret.example.com"}, nil, false, notAfter)
	caPair := certGenECDSA(t, "Secret CA", nil, true, notAfter)
	ignoredSecret := "SUPER-SECRET-IGNORED-CA-KEY"

	serverRec, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "sealed-rsa",
		Type:        "server",
		Certificate: rsaPair.certPEM,
		PrivateKey:  rsaPair.keyPKCS8PEM,
	})
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	clientRec, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "client-no-key",
		Type:        "client",
		Certificate: caPair.certPEM,
		PrivateKey:  ignoredSecret,
	})
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	if clientRec.SealedPrivateKey != nil {
		t.Fatalf("client cert should not seal private key")
	}

	// Verify sealed key opens with the exact label and fails with any other label.
	opened, err := e.vault.Open(serverRec.SealedPrivateKey, certVaultLabelPrefix+serverRec.ID)
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	if opened != rsaPair.keyPKCS8PEM {
		t.Fatalf("opened private key did not match original")
	}
	if _, err := e.vault.Open(serverRec.SealedPrivateKey, certVaultLabelPrefix+certUnknownUUID); err == nil {
		t.Fatalf("expected vault.Open to fail with wrong label")
	}

	// Verify NO plaintext key or ignored secret exists anywhere in store.Dump.
	certAssertNoPlaintextKeyInStore(t, e.store, rsaPair.keyPKCS8PEM, ignoredSecret)

	// Verify wire serialization always returns empty private_key.
	wire := certToWire(certTestTenant, serverRec)
	if wire.PrivateKey != "" {
		t.Fatalf("wire.PrivateKey = %q, want empty", wire.PrivateKey)
	}
}

func TestCertUpdate(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	notAfter1 := certTestEpoch.AddDate(1, 0, 0)
	notAfter2 := certTestEpoch.AddDate(2, 0, 0)
	rsa1 := certGenRSA(t, "v1.example.com", []string{"v1.example.com"}, nil, false, notAfter1)
	ec2 := certGenECDSA(t, "v2.example.com", []string{"v2.example.com", "alt2.example.com"}, false, notAfter2)
	ca1 := certGenECDSA(t, "CA v1", nil, true, notAfter1)
	ca2 := certGenECDSA(t, "CA v2", nil, true, notAfter2)

	srv, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "srv-1",
		Type:        "server",
		Certificate: rsa1.certPEM,
		PrivateKey:  rsa1.keyPKCS1PEM,
	})
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// 1. Renew certificate using the SAME RSA private key (certificate-only update).
	renewedPEM, renewedFP := certGenWithExistingKey(t, rsa1.key, "renewed.example.com", []string{"renewed.example.com"}, notAfter2)
	e.clock.Advance(time.Minute)
	updated, err := e.svc.certUpdate(t.Context(), certTestTenant, srv.ID, certUpdateInput{
		Name:        certPtr("srv-renewed"),
		Description: certPtr("renewed cert"),
		Certificate: certPtr(renewedPEM),
	})
	if err != nil {
		t.Fatalf("cert-only renewal: %v", err)
	}
	if updated.CommonName != "renewed.example.com" || updated.Fingerprint != renewedFP || !updated.ExpireTime.Equal(notAfter2) {
		t.Fatalf("unexpected renewed cert: %+v", updated)
	}

	// 2. Cert-only update with non-matching key fails with ELB.1011.
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, srv.ID, certUpdateInput{
		Certificate: certPtr(ec2.certPEM),
	}); certCodeOf(err) != "ELB.1011" {
		t.Fatalf("mismatched cert-only update: err = %v, want ELB.1011", err)
	}

	// 3. Key-only update with mismatched key fails with ELB.1011.
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, srv.ID, certUpdateInput{
		PrivateKey: certPtr(ec2.keySEC1PEM),
	}); certCodeOf(err) != "ELB.1011" {
		t.Fatalf("mismatched key-only update: err = %v, want ELB.1011", err)
	}

	// 4. Full pair rotation to ECDSA succeeds and re-seals new key.
	e.clock.Advance(time.Minute)
	rotated, err := e.svc.certUpdate(t.Context(), certTestTenant, srv.ID, certUpdateInput{
		Domain:           certPtr("*.v2.example.com"),
		Certificate:      certPtr(ec2.certPEM),
		PrivateKey:       certPtr(ec2.keySEC1PEM),
		AdminStateUp:     certPtr(false),
		ProtectionStatus: certPtr("consoleProtection"),
		ProtectionReason: certPtr("ops lock"),
	})
	if err != nil {
		t.Fatalf("pair rotation: %v", err)
	}
	if rotated.Fingerprint != ec2.fingerprint || rotated.AdminStateUp || rotated.Domain != "*.v2.example.com" {
		t.Fatalf("unexpected rotated cert: %+v", rotated)
	}
	opened, err := e.vault.Open(rotated.SealedPrivateKey, certVaultLabelPrefix+rotated.ID)
	if err != nil || opened != ec2.keySEC1PEM {
		t.Fatalf("re-sealed key mismatch: err=%v", err)
	}
	certAssertNoPlaintextKeyInStore(t, e.store, rsa1.keyPKCS1PEM, ec2.keySEC1PEM)

	// 5. Client CA update: good CA succeeds, non-CA fails with ELB.5051.
	caRec, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "ca-1",
		Type:        "client",
		Certificate: ca1.certPEM,
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, caRec.ID, certUpdateInput{
		Certificate: certPtr(ec2.certPEM),
	}); certCodeOf(err) != "ELB.5051" {
		t.Fatalf("non-CA update: err = %v, want ELB.5051", err)
	}
	caUpdated, err := e.svc.certUpdate(t.Context(), certTestTenant, caRec.ID, certUpdateInput{
		Certificate: certPtr(ca2.certPEM),
	})
	if err != nil {
		t.Fatalf("good CA update: %v", err)
	}
	if caUpdated.Fingerprint != ca2.fingerprint || caUpdated.CommonName != "CA v2" {
		t.Fatalf("unexpected updated CA: %+v", caUpdated)
	}

	// 6. Out-of-scope update fields -> WeiStack.0501; unknown ID -> ELB.8904.
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, srv.ID, certUpdateInput{
		ScmCertificateID: certPtr("scm-1"),
	}); certCodeOf(err) != "WeiStack.0501" {
		t.Fatalf("scm update: err = %v, want WeiStack.0501", err)
	}
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, certUnknownUUID, certUpdateInput{
		Name: certPtr("nope"),
	}); certCodeOf(err) != "ELB.8904" {
		t.Fatalf("unknown update: err = %v, want ELB.8904", err)
	}
}

func TestCertDeleteAndListenerIntegration(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	notAfter := certTestEpoch.AddDate(1, 0, 0)
	srv1 := certGenRSA(t, "default.example.com", []string{"default.example.com"}, nil, false, notAfter)
	srv2 := certGenECDSA(t, "sni.example.com", []string{"sni.example.com"}, false, notAfter)
	ca := certGenECDSA(t, "Client Auth CA", nil, true, notAfter)

	cDefault, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "default-srv",
		Type:        "server",
		Certificate: srv1.certPEM,
		PrivateKey:  srv1.keyPKCS1PEM,
	})
	if err != nil {
		t.Fatalf("create default cert: %v", err)
	}
	cSNI, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "sni-srv",
		Type:        "server",
		Certificate: srv2.certPEM,
		PrivateKey:  srv2.keySEC1PEM,
	})
	if err != nil {
		t.Fatalf("create sni cert: %v", err)
	}
	cCA, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:        "client-ca",
		Type:        "client",
		Certificate: ca.certPEM,
	})
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}

	// Wrong certificate types on HTTPS listener fail with ELB.8902.
	if _, err := e.svc.createListener(t.Context(), certTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Protocol:               "HTTPS",
		ProtocolPort:           certPtr(443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: cCA.ID, // client cert as server cert
	}); certCodeOf(err) != "ELB.8902" {
		t.Fatalf("client cert as default_tls_container_ref: err = %v, want ELB.8902", err)
	}
	if _, err := e.svc.createListener(t.Context(), certTestTenant, createListenerInput{
		LoadBalancerID:          e.lbID,
		Protocol:                "HTTPS",
		ProtocolPort:            certPtr(443),
		PortRangesValid:         true,
		DefaultTLSContainerRef:  cDefault.ID,
		ClientCATLSContainerRef: cSNI.ID, // server cert as client CA
	}); certCodeOf(err) != "ELB.8902" {
		t.Fatalf("server cert as client_ca_tls_container_ref: err = %v, want ELB.8902", err)
	}
	if _, err := e.svc.createListener(t.Context(), certTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Protocol:               "HTTPS",
		ProtocolPort:           certPtr(443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: cDefault.ID,
		SNIContainerRefs:       []string{cCA.ID}, // client cert as SNI
	}); certCodeOf(err) != "ELB.8902" {
		t.Fatalf("client cert in sni_container_refs: err = %v, want ELB.8902", err)
	}

	// Create HTTPS (default), TLS (default + SNI), and QUIC (default + client CA) listeners.
	httpsLsn, err := e.svc.createListener(t.Context(), certTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Name:                   "https-lsn",
		Protocol:               "HTTPS",
		ProtocolPort:           certPtr(443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: cDefault.ID,
	})
	if err != nil {
		t.Fatalf("create HTTPS listener: %v", err)
	}
	tlsLsn, err := e.svc.createListener(t.Context(), certTestTenant, createListenerInput{
		LoadBalancerID:         e.lbID,
		Name:                   "tls-lsn",
		Protocol:               "TLS",
		ProtocolPort:           certPtr(8443),
		PortRangesValid:        true,
		DefaultTLSContainerRef: cDefault.ID,
		SNIContainerRefs:       []string{cSNI.ID},
	})
	if err != nil {
		t.Fatalf("create TLS listener: %v", err)
	}
	quicLsn, err := e.svc.createListener(t.Context(), certTestTenant, createListenerInput{
		LoadBalancerID:          e.lbID,
		Name:                    "quic-lsn",
		Protocol:                "QUIC",
		ProtocolPort:            certPtr(443),
		PortRangesValid:         true,
		DefaultTLSContainerRef:  cDefault.ID,
		ClientCATLSContainerRef: cCA.ID,
	})
	if err != nil {
		t.Fatalf("create QUIC listener: %v", err)
	}

	// All 3 certificates are in use -> DeleteCertificate refused with ELB.8907.
	for _, tc := range []struct {
		label string
		id    string
	}{
		{"default_tls_container_ref", cDefault.ID},
		{"sni_container_refs", cSNI.ID},
		{"client_ca_tls_container_ref", cCA.ID},
	} {
		if err := e.svc.certDelete(t.Context(), certTestTenant, tc.id); certCodeOf(err) != "ELB.8907" {
			t.Fatalf("delete cert in use via %s: err = %v, want ELB.8907", tc.label, err)
		}
	}

	// Clearing domain while cert is used by listener -> ELB.8907.
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, cDefault.ID, certUpdateInput{
		Domain: certPtr(""),
	}); certCodeOf(err) != "ELB.8907" {
		t.Fatalf("clear domain while in use: err = %v, want ELB.8907", err)
	}

	// Delete TLS and QUIC listeners -> SNI and CA certs can now be deleted; default still used by HTTPS.
	if err := e.svc.deleteListener(t.Context(), certTestTenant, tlsLsn.ID); err != nil {
		t.Fatalf("delete TLS listener: %v", err)
	}
	if err := e.svc.deleteListener(t.Context(), certTestTenant, quicLsn.ID); err != nil {
		t.Fatalf("delete QUIC listener: %v", err)
	}
	if err := e.svc.certDelete(t.Context(), certTestTenant, cSNI.ID); err != nil {
		t.Fatalf("delete unbound SNI cert: %v", err)
	}
	if err := e.svc.certDelete(t.Context(), certTestTenant, cCA.ID); err != nil {
		t.Fatalf("delete unbound CA cert: %v", err)
	}
	if err := e.svc.certDelete(t.Context(), certTestTenant, cDefault.ID); certCodeOf(err) != "ELB.8907" {
		t.Fatalf("default cert still used by HTTPS listener: err = %v, want ELB.8907", err)
	}

	// Delete HTTPS listener -> clearing domain and deleting default cert now succeed.
	if err := e.svc.deleteListener(t.Context(), certTestTenant, httpsLsn.ID); err != nil {
		t.Fatalf("delete HTTPS listener: %v", err)
	}
	if _, err := e.svc.certUpdate(t.Context(), certTestTenant, cDefault.ID, certUpdateInput{
		Domain: certPtr(""),
	}); err != nil {
		t.Fatalf("clear domain after listener delete: %v", err)
	}
	if err := e.svc.certDelete(t.Context(), certTestTenant, cDefault.ID); err != nil {
		t.Fatalf("delete default cert: %v", err)
	}
	if _, err := e.svc.certGet(t.Context(), certTestTenant, cDefault.ID); certCodeOf(err) != "ELB.8904" {
		t.Fatalf("get deleted cert: err = %v, want ELB.8904", err)
	}
}

func TestCertListFiltersAndPagination(t *testing.T) {
	t.Parallel()
	e := certNewEnv(t)

	notAfter := certTestEpoch.AddDate(1, 0, 0)
	rsa1 := certGenRSA(t, "alpha.example.com", nil, nil, false, notAfter)
	ec2 := certGenECDSA(t, "beta.example.com", nil, false, notAfter)
	ca3 := certGenECDSA(t, "Gamma CA", nil, true, notAfter)

	c1, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:                "cert-alpha",
		Description:         "desc-alpha",
		Type:                "server",
		Domain:              "alpha.example.com",
		Certificate:         rsa1.certPEM,
		PrivateKey:          rsa1.keyPKCS1PEM,
		AdminStateUp:        certPtr(true),
		EnterpriseProjectID: certPtr(defaultEnterpriseProjectID),
		ProtectionStatus:    "nonProtection",
	})
	if err != nil {
		t.Fatalf("create c1: %v", err)
	}
	c2, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:                "cert-beta",
		Description:         "desc-beta",
		Type:                "server",
		Domain:              "*.beta.example.com",
		Certificate:         ec2.certPEM,
		PrivateKey:          ec2.keySEC1PEM,
		AdminStateUp:        certPtr(false),
		EnterpriseProjectID: certPtr(certCustomEP),
		ProtectionStatus:    "consoleProtection",
		ProtectionReason:    "locked",
	})
	if err != nil {
		t.Fatalf("create c2: %v", err)
	}
	c3, err := e.svc.certCreate(t.Context(), certTestTenant, certCreateInput{
		Name:                "cert-gamma",
		Description:         "desc-gamma",
		Type:                "client",
		Certificate:         ca3.certPEM,
		EnterpriseProjectID: certPtr(defaultEnterpriseProjectID),
	})
	if err != nil {
		t.Fatalf("create c3: %v", err)
	}
	// Seed one cert in another project to verify tenant isolation.
	if _, err := e.svc.certCreate(t.Context(), certTestTenantB, certCreateInput{
		Name:        "other-project-cert",
		Type:        "client",
		Certificate: ca3.certPEM,
	}); err != nil {
		t.Fatalf("create other tenant cert: %v", err)
	}

	// Default list returns 3 sorted ascending by ID.
	all, pi, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 || pi.CurrentCount != 3 || pi.NextMarker != nil {
		t.Fatalf("list all: len=%d pi=%+v", len(all), pi)
	}
	if all[0].ID >= all[1].ID || all[1].ID >= all[2].ID {
		t.Fatalf("not sorted ascending by ID: %s, %s, %s", all[0].ID, all[1].ID, all[2].ID)
	}

	// Marker + limit pagination walks all 3 items cleanly.
	p1, pi1, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		Page: pagination.Marker{Limit: 2},
	})
	if err != nil || len(p1) != 2 || pi1.NextMarker == nil || *pi1.NextMarker != all[1].ID {
		t.Fatalf("page 1: len=%d pi=%+v err=%v", len(p1), pi1, err)
	}
	p2, pi2, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		Page: pagination.Marker{ID: *pi1.NextMarker, Limit: 2},
	})
	if err != nil || len(p2) != 1 || p2[0].ID != all[2].ID || pi2.NextMarker != nil {
		t.Fatalf("page 2: len=%d pi=%+v err=%v", len(p2), pi2, err)
	}

	// Invalid marker -> ELB.8902.
	if _, _, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		Page: pagination.Marker{ID: certUnknownUUID, Limit: 10},
	}); certCodeOf(err) != "ELB.8902" {
		t.Fatalf("invalid marker: err = %v, want ELB.8902", err)
	}

	// Filter by specific attributes matching c2.
	filtered, _, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		IDs:                  []string{c2.ID},
		Names:                []string{"cert-beta"},
		Descriptions:         []string{"desc-beta"},
		AdminStateUp:         certPtr(false),
		Domains:              []string{"*.beta.example.com"},
		Types:                []string{"server"},
		CommonNames:          []string{"beta.example.com"},
		Fingerprints:         []string{ec2.fingerprint},
		ProtectionStatuses:   []string{"consoleProtection"},
		ProtectionReasons:    []string{"locked"},
		EnterpriseProjectIDs: []string{certCustomEP},
	})
	if err != nil || len(filtered) != 1 || filtered[0].ID != c2.ID {
		t.Fatalf("combined filter: got %d err=%v", len(filtered), err)
	}

	// enterprise_project_id=all_granted_eps returns all 3.
	epAll, _, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		EnterpriseProjectIDs: []string{allGrantedEPs},
	})
	if err != nil || len(epAll) != 3 {
		t.Fatalf("all_granted_eps: got %d err=%v", len(epAll), err)
	}

	// Filter by scm_certificate_id or source="scm" returns 0.
	scmNone, _, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		ScmCertificateIDs: []string{"scm-123"},
	})
	if err != nil || len(scmNone) != 0 {
		t.Fatalf("scm filter: got %d err=%v", len(scmNone), err)
	}
	srcNone, _, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		Sources: []string{"scm"},
	})
	if err != nil || len(srcNone) != 0 {
		t.Fatalf("source filter: got %d err=%v", len(srcNone), err)
	}

	// Multi-value filter returns c1 and c3.
	multi, _, err := e.svc.certList(t.Context(), certTestTenant, certListFilter{
		Names: []string{c1.Name, c3.Name},
	})
	if err != nil || len(multi) != 2 {
		t.Fatalf("multi-value filter: got %d err=%v", len(multi), err)
	}
}
