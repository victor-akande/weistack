// Package tlsca is WeiStack's local certificate authority. It lets the
// emulator answer HTTPS requests for real Huawei Cloud host names
// (vpc.ap-southeast-1.myhuaweicloud.com, ...) that clients send through
// it as a proxy: each host gets a certificate signed by a CA created on
// first use and kept on disk, so a client can trust it once.
package tlsca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File names in the CA directory.
const (
	CertFile = "ca.pem"
	keyFile  = "ca-key.pem"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 397 * 24 * time.Hour // the longest browsers accept
	commonName   = "WeiStack local CA"
)

// Authority issues certificates for host names. It is safe for
// concurrent use.
type Authority struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	// leafKey is shared by every issued certificate: generating a key
	// per host would cost far more than it protects in a local emulator.
	leafKey *ecdsa.PrivateKey
	now     func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// Load reads the CA from dir, creating it (and dir) on first use. An
// empty dir gives an in-memory CA that lasts as long as the process.
func Load(dir string) (*Authority, error) {
	if dir == "" {
		return generate()
	}
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, keyFile)
	certPEM, certErr := os.ReadFile(certPath) //nolint:gosec // operator-chosen directory
	keyPEM, keyErr := os.ReadFile(keyPath)    //nolint:gosec // operator-chosen directory
	switch {
	case certErr == nil && keyErr == nil:
		return parse(certPEM, keyPEM)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		a, err := generate()
		if err != nil {
			return nil, err
		}
		if err := a.save(dir); err != nil {
			return nil, err
		}
		return a, nil
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("tlsca: reading %s: %w", certPath, certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("tlsca: reading %s: %w", keyPath, keyErr)
	}
	return nil, fmt.Errorf("tlsca: %s holds only half of a CA (%s or %s is missing); delete the directory to create a new one", dir, CertFile, keyFile)
}

func newAuthority(cert *x509.Certificate, certPEM []byte, key crypto.Signer) (*Authority, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsca: generating key: %w", err)
	}
	return &Authority{cert: cert, certPEM: certPEM, key: key, leafKey: leafKey, now: time.Now, leaves: map[string]*tls.Certificate{}}, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func generate() (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsca: generating CA key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"WeiStack"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("tlsca: creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newAuthority(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key)
}

func parse(certPEM, keyPEM []byte) (*Authority, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("tlsca: the CA files are not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsca: parsing CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("tlsca: the CA certificate is not a CA")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsca: parsing CA key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlsca: the CA key cannot sign")
	}
	return newAuthority(cert, certPEM, key)
}

func (a *Authority) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tlsca: creating %s: %w", dir, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return fmt.Errorf("tlsca: saving key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, CertFile), a.certPEM, 0o644); err != nil { //nolint:gosec // a public certificate
		return fmt.Errorf("tlsca: saving certificate: %w", err)
	}
	return nil
}

// CertPEM returns the CA certificate, for clients to trust.
func (a *Authority) CertPEM() []byte { return a.certPEM }

// Pool returns a pool holding the CA, for tests and in-process clients.
func (a *Authority) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.cert)
	return p
}

// Certificate returns a certificate for host, issuing it on first use.
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("tlsca: no host name")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leaves[host]; ok && a.now().Before(c.Leaf.NotAfter.Add(-time.Hour)) {
		return c, nil
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := a.now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("tlsca: issuing a certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: a.leafKey, Leaf: leaf}
	a.leaves[host] = c
	return c, nil
}

// ServerConfig returns a TLS configuration that presents a certificate
// for the name the client asks for, or for fallback when it sends none.
func (a *Authority) ServerConfig(fallback string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = fallback
			}
			return a.Certificate(name)
		},
	}
}
