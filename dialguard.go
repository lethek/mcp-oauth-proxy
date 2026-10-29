package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// Addresses refused whatever the allowed networks say. Link-local is where
// cloud metadata services usually answer, and 100.100.100.200 is the metadata
// address of at least one cloud that sits inside 100.64.0.0/10, which is
// otherwise a range an operator may legitimately allow.
var (
	metadataAddr = netip.MustParseAddr("100.100.100.200")
	thisNetwork  = netip.MustParsePrefix("0.0.0.0/8")
	// NAT64 is an IPv4 destination in disguise, so allowing a private range
	// must not allow the same range through a gateway. See isPublicIP.
	nat64Prefixes = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	}
)

// neverDialable reports whether an address is refused unconditionally.
func neverDialable(a netip.Addr) bool {
	if a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a == metadataAddr || thisNetwork.Contains(a) {
		return true
	}
	for _, p := range nat64Prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dialGuard returns a net.Dialer Control hook. It runs after DNS resolution
// with the address about to be dialled, so a name that resolves somewhere else
// between a check and the connection cannot slip past.
//
// An address is admitted when it is public, or when it falls in nets. With
// requireListed (plain http, where nothing protects the credential in transit)
// it must be in nets even if it is public. The never-dialable set is refused
// first, so no entry in nets can open it.
func dialGuard(nets []netip.Prefix, requireListed bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("could not parse the address %q", host)
		}
		// ::ffff:10.0.0.1 is the IPv4 address 10.0.0.1, and must be judged as
		// that or it would dodge every IPv4 rule below.
		addr = addr.Unmap()

		if neverDialable(addr) {
			return fmt.Errorf("refusing to connect to the reserved address %s", addr)
		}
		if inNets(nets, addr) {
			return nil
		}
		if requireListed {
			return fmt.Errorf("refusing to connect to %s over plain http: it is not in an allowed network", addr)
		}
		if !isPublicIP(net.IP(addr.AsSlice())) {
			return fmt.Errorf("refusing to connect to the non-public address %s", addr)
		}
		return nil
	}
}

// hostPattern is one ALLOWED_UPSTREAM_HOSTS entry: a host and a port, matched
// exactly. The port is part of it because a name alone would also admit every
// other service on that machine.
type hostPattern struct {
	Host string
	Port string
}

// validateAdminUpstream checks an upstream URL supplied through the admin UI.
// It is pure, so it cannot see what a name resolves to. Hostnames are
// authorised here and destination addresses at dial time by dialGuard, which
// is why the two lists are independent.
func validateAdminUpstream(raw string, hosts []hostPattern, nets []netip.Prefix) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("must use http or https")
	}
	if u.Hostname() == "" {
		return errors.New("has no host")
	}
	// The URL is shown on the consent page and logged, and userinfo would put a
	// credential in both.
	if u.User != nil {
		return errors.New("must not carry a username or password")
	}

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	if !matchesHost(hosts, host, port) {
		return fmt.Errorf("%s:%s is not in the allowed upstream hosts", host, port)
	}

	if u.Scheme == "http" {
		// A literal address can be judged now. A name cannot, so it is accepted
		// only when some network could admit it, and dialGuard (requireListed)
		// checks the address it actually resolves to on every connection.
		if addr, err := netip.ParseAddr(host); err == nil {
			if !inNets(nets, addr.Unmap()) {
				return fmt.Errorf("http is only allowed to an address in the allowed upstream networks, and %s is not in one", addr)
			}
		} else if len(nets) == 0 {
			return errors.New("http is only allowed to an address in the allowed upstream networks, and none are configured")
		}
	}
	return nil
}

func matchesHost(hosts []hostPattern, host, port string) bool {
	for _, h := range hosts {
		if strings.EqualFold(h.Host, host) && h.Port == port {
			return true
		}
	}
	return false
}

func inNets(nets []netip.Prefix, a netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
