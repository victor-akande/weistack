package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/victor-akande/weistack/internal/core/config"
	"github.com/victor-akande/weistack/internal/tlsca"
)

// -lan serves other machines on a listener of its own: on every
// interface, over HTTPS with certificates from the local CA, admitting
// only the client addresses -lan-clients allows. The server checks the
// credentials of every request it carries (server.NetworkHandler).

// listenLAN opens the -lan listener.
func listenLAN(ctx context.Context, cfg config.Config, ca *tlsca.Authority, log *slog.Logger) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(cfg.LANPort)))
	if err != nil {
		return nil, fmt.Errorf("-lan: listening: %w", err)
	}
	admitted := &clientFilter{Listener: ln, cfg: cfg, log: log, logged: map[netip.Addr]time.Time{}}
	return tls.NewListener(admitted, lanTLS(ca)), nil
}

// lanTLS presents a certificate for the name the client asks for, or,
// as clients that address WeiStack by IP send no name, for the address
// the client connected to.
func lanTLS(ca *tlsca.Authority) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				return ca.Certificate(hello.ServerName)
			}
			host, _, err := net.SplitHostPort(hello.Conn.LocalAddr().String())
			if err != nil {
				return nil, err
			}
			if a, err := netip.ParseAddr(host); err == nil {
				host = a.Unmap().WithZone("").String()
			}
			return ca.Certificate(host)
		},
	}
}

// clientFilter closes connections from addresses -lan does not admit.
type clientFilter struct {
	net.Listener
	cfg config.Config
	log *slog.Logger

	mu     sync.Mutex
	logged map[netip.Addr]time.Time // when each refused address was last logged
}

func (f *clientFilter) Accept() (net.Conn, error) {
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err == nil && f.cfg.LANClientAllowed(ap.Addr()) {
			return c, nil
		}
		_ = c.Close()
		f.refused(ap.Addr(), c.RemoteAddr().String())
	}
}

// refused logs a refused client, once a minute per address, so a scan
// does not flood the log.
func (f *clientFilter) refused(addr netip.Addr, remote string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if last, ok := f.logged[addr]; ok && now.Sub(last) < time.Minute {
		return
	}
	if len(f.logged) > 4096 {
		clear(f.logged)
	}
	f.logged[addr] = now
	f.log.Warn("-lan refused a client outside -lan-clients", "remote", remote,
		"fix", "add its address range to -lan-clients (WEISTACK_LAN_CLIENTS)")
}

// lanURLs are the addresses other machines can use: one per interface
// address that is neither loopback nor link-local.
func lanURLs(port int) []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr().Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, "https://"+net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	return out
}
