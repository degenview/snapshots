package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver decides which IP address a request came from.
//
// By default only the TCP peer counts: forwarding headers are attacker
// controlled and ignored. When the peer is inside one of the trusted proxy
// ranges, the configured header is read from the right: the first address not
// itself a trusted proxy is the client, so entries a client prepends to
// X-Forwarded-For cannot choose their own identity.
type Resolver struct {
	trusted []netip.Prefix
	anyPeer bool
	header  string
}

// NewResolver returns a Resolver. With no trusted prefixes (and anyPeer false)
// or no header it always returns the peer address.
//
// anyPeer trusts the header from every peer. Use it only when the service is
// reachable solely through a proxy that sets the header itself (a platform
// ingress), since otherwise any client could choose its own address. In that
// mode the header's last entry is the client.
func NewResolver(trusted []netip.Prefix, anyPeer bool, header string) *Resolver {
	return &Resolver{trusted: trusted, anyPeer: anyPeer, header: http.CanonicalHeaderKey(strings.TrimSpace(header))}
}

// Client returns the client address for r. ok is false if not even the peer
// address can be parsed.
func (rv *Resolver) Client(r *http.Request) (netip.Addr, bool) {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok {
		return netip.Addr{}, false
	}
	if rv.header == "" || (!rv.anyPeer && !rv.isTrusted(peer)) {
		return peer, true
	}
	var parts []string
	for _, v := range r.Header.Values(rv.header) {
		parts = append(parts, strings.Split(v, ",")...)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer, true // garbage: do not guess
		}
		a = a.Unmap()
		if rv.isTrusted(a) {
			continue
		}
		return a, true
	}
	return peer, true
}

func (rv *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range rv.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func peerAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	if i := strings.IndexByte(host, '%'); i >= 0 { // zone
		host = host[:i]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Key is the bucket key for an address. IPv6 clients are grouped by /64, since
// one subscriber commonly controls the whole prefix.
func Key(a netip.Addr) string {
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}
