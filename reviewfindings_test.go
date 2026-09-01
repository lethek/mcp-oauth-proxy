package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"testing"
)

// TestRewrittenUnauthorizedIsDecodable checks a claim from review: the 401
// rewrite replaces the body but leaves the upstream's Content-Encoding, so a
// client that asked for gzip is handed an uncompressed body labelled gzip and
// cannot read the advice the rewrite exists to deliver.
//
// Accept-Encoding is set explicitly because Go's transport otherwise adds it and
// decompresses transparently, which hides the bug.
func TestRewrittenUnauthorizedIsDecodable(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)
	h.gzipRefusal.Store(true)
	h.refuseAlpha.Store(true)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)
	h.enrol("user-42 (alice)", "alpha", map[string]string{"Authorization": "Bearer revoked"})

	req, err := http.NewRequest("POST", h.proxy.URL+"/alpha/mcp", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}

	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		// The body is the rewrite's own plaintext JSON, so a surviving encoding
		// header is a lie a conforming client will act on.
		if _, err := gzip.NewReader(bytes.NewReader(buf.Bytes())); err != nil {
			t.Errorf("Content-Encoding is %q but the body is not %s decodable: %v", enc, enc, err)
		}
	}
	if !strings.Contains(buf.String(), "/settings") {
		t.Errorf("the client could not read the enrolment advice; body = %q", buf.String())
	}
}

// TestEncodedDotSegmentsDoNotReachUpstream checks a claim from review: ServeMux
// cleans literal ".." but not "%2e%2e", so an encoded traversal could be
// forwarded to the upstream with the injected credential attached.
func TestEncodedDotSegmentsDoNotReachUpstream(t *testing.T) {
	h := newHarnessWith(t, perUserTargets)

	const redirect = "https://client.example/callback"
	clientID := h.register(redirect)
	access, _ := h.tokensFor(clientID, redirect, h.srv.cfg.Targets[0].Resource)
	h.enrol("user-42 (alice)", "alpha", map[string]string{"Authorization": "Bearer alices-token"})

	resp := h.mcpRequest("/alpha/mcp/%2e%2e/%2e%2e/escaped", access)
	resp.Body.Close()

	select {
	case got := <-h.upstreamPaths:
		if strings.Contains(got, "..") || strings.Contains(strings.ToLower(got), "%2e") {
			t.Errorf("upstream received %q: a traversal escaped the target's base path "+
				"with the injected credential attached", got)
		}
	default:
		// Nothing forwarded is the safe outcome.
	}
}
