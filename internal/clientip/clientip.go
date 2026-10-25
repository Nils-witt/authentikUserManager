// Package clientip determines the IP address of the client of a request,
// trusting the X-Forwarded-For header only when trusted proxies sent it.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// Resolver returns client IP addresses. The zero value trusts no proxy.
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver returns a Resolver trusting the proxies in trusted, IP
// addresses or CIDR prefixes such as "10.0.0.0/8".
func NewResolver(trusted []string) (Resolver, error) {
	var r Resolver
	for _, t := range trusted {
		prefix, err := netip.ParsePrefix(t)
		if err != nil {
			addr, addrErr := netip.ParseAddr(t)
			if addrErr != nil {
				return Resolver{}, fmt.Errorf("clientip: %q is neither an IP address nor a CIDR prefix", t)
			}
			prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		r.trusted = append(r.trusted, prefix.Masked())
	}
	return r, nil
}

// IP returns the client's IP address of req. When the peer is a trusted
// proxy, it is the right-most address of X-Forwarded-For that is not a
// trusted proxy itself, since clients can forge the addresses left of it.
func (r Resolver) IP(req *http.Request) string {
	peer := remoteAddr(req)
	if !r.isTrusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(req.Header.Values("X-Forwarded-For"), ","), ",")
	for _, hop := range slices.Backward(hops) {
		addr, err := netip.ParseAddr(strings.TrimSpace(hop))
		if err != nil {
			// A malformed entry ends the trusted chain.
			return peer.String()
		}
		if addr = addr.Unmap(); !r.isTrusted(addr) {
			return addr.String()
		}
		peer = addr
	}
	return peer.String()
}

func (r Resolver) isTrusted(addr netip.Addr) bool {
	return addr.IsValid() && slices.ContainsFunc(r.trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// remoteAddr returns the address of the peer of req, invalid when unknown.
func remoteAddr(req *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}
