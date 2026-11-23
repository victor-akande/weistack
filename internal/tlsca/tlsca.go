// Package tlsca is WeiStack's local certificate authority. It lets the
// emulator answer HTTPS requests for real Huawei Cloud host names
// (vpc.ap-southeast-1.myhuaweicloud.com, ...) that clients send through
// it as a proxy: each host gets a certificate signed by a CA created on
// first use and kept on disk, so a client can trust it once.
//
// Clients trust the CA as much as any public one, so a CA that could sign
// for any name would let whoever holds its key impersonate any site to
// them. A new CA is therefore limited by name constraints (RFC 5280
// 4.2.1.10) to the names WeiStack answers: the emulated domains, local
// names and private addresses. CAs created before v0.3 have none and are
// reported by Constrained.
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
	KeyFile  = "ca-key.pem"
)

// DefaultDomain is Huawei Cloud's, which every new CA may sign for.
const DefaultDomain = "myhuaweicloud.com"

// localDomains are names that resolve only on a machine or a local
// network: a CA may sign for them and their subdomains.
var localDomains = []string{"localhost", "local", "lan", "internal", "home.arpa"}

// localRanges are the addresses a CA may sign for: loopback, private,
// shared (carrier-grade NAT, as VPN meshes use) and link-local.
var localRanges = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

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

// createWait is how long Load waits for another process that is creating
// the CA in the same directory.
const createWait = 5 * time.Second

// errClaimed means another process created the CA key first.
var errClaimed = errors.New("tlsca: another process is creating the CA")

// Load reads the CA from dir, creating it (and dir) on first use. An
// empty dir gives an in-memory CA that lasts as long as the process. A new
// CA may sign for DefaultDomain, domains, local names and private
// addresses, and nothing else.
//
// Several processes may start on the same new directory at once: the one
// that creates the key file creates the CA, and the others wait for its
// certificate, which is written last (see create).
func Load(dir string, domains ...string) (*Authority, error) {
	if dir == "" {
		return generate(domains)
	}
	return load(dir, domains, createWait)
}

func load(dir string, domains []string, wait time.Duration) (*Authority, error) {
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	half := fmt.Errorf("tlsca: %s holds only half of a CA (%s or %s is missing); delete the directory to create a new one", dir, CertFile, KeyFile)
	deadline := time.Now().Add(wait)
	for {
		// The certificate first: once it exists, the key is complete.
		certPEM, certErr := os.ReadFile(certPath) //nolint:gosec // operator-chosen directory
		keyPEM, keyErr := os.ReadFile(keyPath)    //nolint:gosec // operator-chosen directory
		certMissing, keyMissing := errors.Is(certErr, os.ErrNotExist), errors.Is(keyErr, os.ErrNotExist)
		switch {
		case certErr == nil && keyErr == nil:
			return parse(certPEM, keyPEM)
		case certErr != nil && !certMissing:
			return nil, fmt.Errorf("tlsca: reading %s: %w", certPath, certErr)
		case keyErr != nil && !keyMissing:
			return nil, fmt.Errorf("tlsca: reading %s: %w", keyPath, keyErr)
		case !certMissing: // a certificate without its key
			return nil, half
		case keyMissing:
			a, err := create(dir, domains)
			if !errors.Is(err, errClaimed) {
				return a, err
			}
		}
		// A key without its certificate: another process is creating the
		// CA, or one died while doing so.
		if time.Now().After(deadline) {
			return nil, half
		}
		time.Sleep(20 * time.Millisecond)
	}
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

func generate(domains []string) (*Authority, error) {
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
		// RFC 5280 says name constraints MUST be critical, so a client
		// that cannot check them refuses the CA rather than ignores them.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDomains(domains),
	}
	for _, r := range localRanges {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return nil, err
		}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
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

// create makes a new CA in dir. The key file is created exclusively, so
// of several processes starting at once only one creates the CA; the
// others get errClaimed. The certificate is renamed into place last, so a
// reader that finds it also finds the whole key.
func create(dir string, domains []string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsca: creating %s: %w", dir, err)
	}
	a, err := generate(domains)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, KeyFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-chosen directory
	if errors.Is(err, os.ErrExist) {
		return nil, errClaimed
	}
	if err != nil {
		return nil, fmt.Errorf("tlsca: saving key: %w", err)
	}
	if err := writeAndClose(f, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, fmt.Errorf("tlsca: saving key: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".ca-*.pem")
	if err != nil {
		return nil, fmt.Errorf("tlsca: saving certificate: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // fails harmlessly once renamed
	if err := writeAndClose(tmp, a.certPEM); err != nil {
		return nil, fmt.Errorf("tlsca: saving certificate: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // a public certificate
		return nil, fmt.Errorf("tlsca: saving certificate: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, CertFile)); err != nil {
		return nil, fmt.Errorf("tlsca: saving certificate: %w", err)
	}
	return a, nil
}

func writeAndClose(f *os.File, data []byte) error {
	_, werr := f.Write(data)
	serr := f.Sync()
	return errors.Join(werr, serr, f.Close())
}

// CertPEM returns the CA certificate, for clients to trust.
func (a *Authority) CertPEM() []byte { return a.certPEM }

// Pool returns a pool holding the CA, for tests and in-process clients.
func (a *Authority) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.cert)
	return p
}

// Certificate returns a certificate for host, issuing it on first use. A
// constrained CA refuses hosts outside its constraints, whose
// certificates every client would reject.
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("tlsca: no host name")
	}
	if !a.Permits(host) {
		return nil, fmt.Errorf("tlsca: the CA does not sign for %s (it signs for %s, local names and private addresses)",
			host, strings.Join(a.cert.PermittedDNSDomains, ", "))
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
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		// An address goes only in the subject alternative name, with an
		// empty subject (RFC 5280 4.1.2.6). OpenSSL checks a common name
		// that looks like a host name against the CA's DNS name
		// constraints, and an address is under none of them, so a
		// common name would make curl, Python and every other OpenSSL
		// client refuse the certificate.
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.Subject = pkix.Name{CommonName: host}
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

// permittedDomains are the DNS names a new CA may sign for, without
// duplicates.
func permittedDomains(domains []string) []string {
	out := []string{DefaultDomain}
	seen := map[string]bool{DefaultDomain: true}
	for _, d := range append(append([]string(nil), domains...), localDomains...) {
		d = strings.ToLower(strings.Trim(d, "."))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// Constrained reports whether the CA is limited by name constraints, as
// every CA created since v0.3 is.
func (a *Authority) Constrained() bool {
	return len(a.cert.PermittedDNSDomains) > 0 || len(a.cert.PermittedIPRanges) > 0
}

// Permits reports whether the CA may sign for host, a name or an
// address. An unconstrained CA signs for anything.
func (a *Authority) Permits(host string) bool {
	if !a.Constrained() {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range a.cert.PermittedIPRanges {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range a.cert.PermittedDNSDomains {
		// As RFC 5280 and crypto/x509 read them: "example.com" is the
		// domain and its subdomains, ".example.com" only its subdomains.
		if strings.HasPrefix(d, ".") {
			if strings.HasSuffix(host, d) {
				return true
			}
		} else if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
