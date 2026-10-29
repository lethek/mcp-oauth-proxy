package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDialGuard(t *testing.T) {
	nets := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		// Listing the metadata address's whole range must not open it.
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		// Each wraps 169.254.169.254, so listing the wrapper must not open it.
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("2001::/32"),
		netip.MustParsePrefix("::1/128"),
	}

	for _, tc := range []struct {
		name          string
		addr          string
		nets          []netip.Prefix
		requireListed bool
		wantErr       string // empty means the dial is admitted
	}{
		{name: "public", addr: "93.184.216.34", wantErr: ""},
		{name: "public v6", addr: "2606:2800:220::", wantErr: ""},
		{name: "public but http needs a listed network", addr: "93.184.216.34", requireListed: true, wantErr: "plain http"},
		{name: "private without an entry", addr: "10.1.2.3", wantErr: "non-public"},
		{name: "private with an entry", addr: "10.1.2.3", nets: nets, wantErr: ""},
		{name: "private with an entry over http", addr: "10.1.2.3", nets: nets, requireListed: true, wantErr: ""},
		{name: "private outside the entry", addr: "192.168.1.1", nets: nets, wantErr: "non-public"},
		{name: "loopback needs its own entry", addr: "127.0.0.1", nets: nets, wantErr: "non-public"},
		{name: "loopback with an entry", addr: "127.0.0.1", nets: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, wantErr: ""},
		{name: "link-local", addr: "169.254.169.254", nets: nets, wantErr: "reserved"},
		{name: "link-local v6", addr: "fe80::1", wantErr: "reserved"},
		{name: "metadata address even when its range is listed", addr: "100.100.100.200", nets: nets, wantErr: "reserved"},
		{name: "rest of 100.64.0.0/10 needs an entry", addr: "100.64.0.1", wantErr: "non-public"},
		{name: "rest of 100.64.0.0/10 with an entry", addr: "100.127.255.254", nets: nets, wantErr: ""},
		{name: "this network", addr: "0.1.2.3", nets: nets, wantErr: "reserved"},
		{name: "multicast", addr: "224.0.0.1", nets: nets, wantErr: "reserved"},
		{name: "unspecified v6", addr: "::", wantErr: "reserved"},
		{name: "NAT64", addr: "64:ff9b::a00:1", nets: nets, wantErr: "reserved"},
		{name: "NAT64 local-use prefix", addr: "64:ff9b:1::a00:1", wantErr: "reserved"},
		{name: "6to4 wrapping link-local", addr: "2002:a9fe:a9fe::", nets: nets, wantErr: "reserved"},
		{name: "IPv4-compatible wrapping link-local", addr: "::169.254.169.254", nets: nets, wantErr: "reserved"},
		// Teredo stores the v4 address with every bit flipped.
		{name: "Teredo wrapping link-local", addr: "2001::5601:5601", nets: nets, wantErr: "reserved"},
		{name: "IPv6 loopback can still be listed", addr: "::1", nets: nets, wantErr: ""},
		{name: "zoned NAT64", addr: "64:ff9b::a00:1%eth0", nets: nets, wantErr: "reserved"},
		{name: "zoned listed private", addr: "fd00::1%eth0", nets: []netip.Prefix{netip.MustParsePrefix("fd00::/8")}, wantErr: ""},
		{name: "0.0.0.0", addr: "0.0.0.0", nets: nets, wantErr: "reserved"},
		{name: "link-local multicast v6", addr: "ff02::1", nets: nets, wantErr: "reserved"},
		{name: "mapped this-network", addr: "::ffff:0.0.0.1", nets: nets, wantErr: "reserved"},
		{name: "NAT64 local-use prefix listed in nets", addr: "64:ff9b:1::a00:1", nets: nets, wantErr: "reserved"},
		{name: "mapped private without an entry", addr: "::ffff:10.1.2.3", wantErr: "non-public"},
		{name: "mapped private with an entry", addr: "::ffff:10.1.2.3", nets: nets, wantErr: ""},
		{name: "mapped link-local", addr: "::ffff:169.254.169.254", nets: nets, wantErr: "reserved"},
		{name: "mapped metadata address", addr: "::ffff:100.100.100.200", nets: nets, wantErr: "reserved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := tc.addr
			if strings.Contains(addr, ":") {
				addr = "[" + addr + "]"
			}
			err := dialGuard(tc.nets, tc.requireListed)("tcp", addr+":443", nil)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("dial to %s refused: %v", tc.addr, err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("dial to %s admitted, want an error containing %q", tc.addr, tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("dial to %s: err = %v, want it to contain %q", tc.addr, err, tc.wantErr)
			}
		})
	}

	t.Run("a hostname is not dialled", func(t *testing.T) {
		if err := dialGuard(nil, false)("tcp", "example.com:443", nil); err == nil {
			t.Fatal("a non-address was admitted")
		}
	})
}

func TestValidateAdminUpstream(t *testing.T) {
	hosts := []hostPattern{
		{Host: "mcp.example.com", Port: "443"},
		{Host: "internal.example", Port: "8080"},
		{Host: "10.0.0.5", Port: "8080"},
		{Host: "192.168.1.9", Port: "80"},
		{Host: "169.254.169.254", Port: "8080"},
		{Host: "2606:2800:220::", Port: "443"},
		{Host: "fd00::5", Port: "8080"},
		{Host: "fe80::1", Port: "8080"},
		{Host: "::ffff:10.0.0.5", Port: "8080"},
	}
	nets := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	for _, tc := range []struct {
		name    string
		raw     string
		nets    []netip.Prefix
		wantErr string
	}{
		{name: "https on a listed host", raw: "https://mcp.example.com/mcp"},
		{name: "host match ignores case", raw: "https://MCP.example.com/mcp"},
		{name: "http on a listed literal in nets", raw: "http://10.0.0.5:8080/mcp", nets: nets},
		{name: "http on a listed name when a network could admit it", raw: "http://internal.example:8080/mcp", nets: nets},
		{name: "userinfo", raw: "https://user:pass@mcp.example.com/mcp", wantErr: "username or password"},
		{name: "username only", raw: "https://user@mcp.example.com/mcp", wantErr: "username or password"},
		{name: "host outside the list", raw: "https://evil.example/mcp", wantErr: "not in the allowed upstream hosts"},
		{name: "listed host on another port", raw: "https://mcp.example.com:8443/mcp", wantErr: "not in the allowed upstream hosts"},
		{name: "default port is checked", raw: "http://internal.example/mcp", nets: nets, wantErr: "not in the allowed upstream hosts"},
		{name: "http on a literal outside nets", raw: "http://192.168.1.9/mcp", nets: nets, wantErr: "not in one"},
		{name: "http on a name with no networks", raw: "http://internal.example:8080/mcp", wantErr: "none are configured"},
		{name: "https on a reserved literal", raw: "https://169.254.169.254:8080/mcp", wantErr: "reserved"},
		{name: "http on a reserved literal even in nets", raw: "http://169.254.169.254:8080/mcp", nets: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}, wantErr: "reserved"},
		{name: "https on a bracketed v6 literal", raw: "https://[2606:2800:220::]:443/mcp"},
		{name: "http on a bracketed v6 literal in nets", raw: "http://[fd00::5]:8080/mcp", nets: []netip.Prefix{netip.MustParsePrefix("fd00::/8")}},
		{name: "bracketed link-local literal", raw: "https://[fe80::1]:8080/mcp", wantErr: "reserved"},
		{name: "mapped literal with nets", raw: "http://[::ffff:10.0.0.5]:8080/mcp", nets: nets},
		{name: "mapped literal without nets", raw: "http://[::ffff:10.0.0.5]:8080/mcp", wantErr: "not in one"},
		{name: "other scheme", raw: "ftp://mcp.example.com/mcp", wantErr: "http or https"},
		{name: "no host", raw: "https:///mcp", wantErr: "no host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAdminUpstream(tc.raw, hosts, tc.nets)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("rejected: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("accepted, want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
