package main

import (
	"fmt"
	"net/url"
	"strings"
)

// validateRedirectURI decides whether a client may register a redirect target.
//
// url.Parse on its own accepts "javascript:alert(1)", "data:...", the empty
// string and bare relative paths, so it is not a check at all. The rules here
// are those of OAuth 2.1 and RFC 8252: https anywhere, http only on loopback
// where there is no network to intercept, and private-use schemes for native
// apps, which RFC 8252 section 7.1 requires to contain a dot.
func validateRedirectURI(raw string) error {
	if raw == "" {
		return fmt.Errorf("redirect_uri is empty")
	}
	// Registration is anonymous and a client row outlives it by a month, so an
	// unbounded URI is a way to fill the database from outside. No legitimate
	// redirect target comes close to this.
	if len(raw) > maxRedirectURILen {
		return fmt.Errorf("redirect_uri is longer than %d bytes", maxRedirectURILen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("unparseable redirect_uri %q: %w", raw, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("redirect_uri %q must be absolute", raw)
	}
	// "https://accounts.google.com@evil.example/cb" parses with Host
	// evil.example, and the consent screen prints the string as given. A reader
	// sees a name they trust at the front and approves a redirect to somewhere
	// else. That screen is the confused-deputy defence, so a URI which
	// misrepresents its own destination must not reach it.
	if u.User != nil {
		return fmt.Errorf("redirect_uri %q must not contain a username or password", raw)
	}
	// RFC 6749 section 3.1.2: the endpoint URI must not include a fragment. A
	// fragment would also be dropped on the wire, so a client relying on one is
	// already broken.
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect_uri %q must not contain a fragment", raw)
	}

	// A private-use scheme belongs to a native client, which receives the
	// redirect through the operating system rather than the network, so the
	// transport rule below does not apply to it.
	if u.Scheme != "http" && u.Scheme != "https" {
		if strings.Contains(u.Scheme, ".") {
			return nil
		}
		return fmt.Errorf("redirect_uri %q uses unsupported scheme %q", raw, u.Scheme)
	}

	if u.Host == "" {
		return fmt.Errorf("redirect_uri %q has no host", raw)
	}
	if err := secureTransport(u); err != nil {
		return fmt.Errorf("redirect_uri %q %w", raw, err)
	}
	return nil
}
