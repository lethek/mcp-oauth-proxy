package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateCIMDURL(t *testing.T) {
	if _, err := validateCIMDURL("https://client.example/mcp"); err != nil {
		t.Errorf("a well-formed URL was rejected: %v", err)
	}

	for name, raw := range map[string]string{
		"http":             "http://client.example/mcp",
		"no path":          "https://client.example",
		"bare slash":       "https://client.example/",
		"fragment":         "https://client.example/mcp#x",
		"userinfo":         "https://user:pw@client.example/mcp",
		"single dot":       "https://client.example/./mcp",
		"double dot":       "https://client.example/a/../mcp",
		"no host":          "https:///mcp",
		"not a url at all": "::::",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := validateCIMDURL(raw); err == nil {
				t.Errorf("accepted %q", raw)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	for raw, want := range map[string]bool{
		"93.184.216.34":   true,
		"2606:2800:220::": true,
		"127.0.0.1":       false,
		"::1":             false,
		"10.0.0.99":       false,
		"192.168.1.1":     false,
		"172.16.5.4":      false,
		"169.254.1.1":     false,
		"100.64.0.1":      false, // carrier-grade NAT, where overlays sit
		"0.0.0.0":         false,
	} {
		if got := isPublicIP(net.ParseIP(raw)); got != want {
			t.Errorf("isPublicIP(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestParseCIMD(t *testing.T) {
	const id = "https://client.example/mcp"
	good := map[string]any{
		"client_id":     id,
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://client.example/callback"},
	}

	t.Run("accepts a valid document", func(t *testing.T) {
		c, err := parseCIMD(id, mustJSON(t, good))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.ID != id || c.Name != "Test Client" || len(c.RedirectURIs) != 1 {
			t.Errorf("parsed as %+v", c)
		}
	})

	// The identity claim is the whole security property: without the comparison
	// any document could assert it belongs to a client hosted elsewhere.
	t.Run("rejects a document claiming a different client_id", func(t *testing.T) {
		doc := map[string]any{
			"client_id":     "https://someone-else.example/mcp",
			"redirect_uris": []string{"https://client.example/callback"},
		}
		if _, err := parseCIMD(id, mustJSON(t, doc)); err == nil {
			t.Fatal("accepted a document whose client_id did not match the URL")
		}
	})

	for name, doc := range map[string]map[string]any{
		"a client secret": {
			"client_id":     id,
			"client_secret": "shh",
			"redirect_uris": []string{"https://client.example/callback"},
		},
		"a confidential auth method": {
			"client_id":                  id,
			"token_endpoint_auth_method": "client_secret_basic",
			"redirect_uris":              []string{"https://client.example/callback"},
		},
		"no redirect uris": {
			"client_id": id,
		},
		"an unusable redirect uri": {
			"client_id":     id,
			"redirect_uris": []string{"javascript:alert(1)"},
		},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := parseCIMD(id, mustJSON(t, doc)); err == nil {
				t.Errorf("accepted a document with %s", name)
			}
		})
	}

	t.Run("falls back to the URL when unnamed", func(t *testing.T) {
		doc := map[string]any{"client_id": id, "redirect_uris": []string{"https://client.example/callback"}}
		c, err := parseCIMD(id, mustJSON(t, doc))
		if err != nil {
			t.Fatal(err)
		}
		if c.Name != id {
			t.Errorf("Name = %q, want the URL so consent still shows something", c.Name)
		}
	})
}

// TestCIMDRefusesPrivateAddresses is the SSRF guard. The client_id is chosen by
// whoever calls /authorize, so without this the proxy would fetch any address it
// can reach on behalf of an anonymous caller.
func TestCIMDRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the guard let a request through to a loopback address")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// The guarded constructor, as production uses it.
	c := newCIMDClient()
	_, err := c.Fetch(context.Background(), srv.URL+"/mcp")
	if err == nil {
		t.Fatal("fetching a loopback address succeeded")
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Errorf("err = %v, want it to name the address refusal", err)
	}
}

func TestCIMDFetch(t *testing.T) {
	var doc []byte
	var contentType string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(doc)
	}))
	defer srv.Close()

	id := srv.URL + "/mcp"
	// Unguarded, because the document under test is necessarily on loopback.
	c := newCIMD(false)
	c.http.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	t.Run("fetches and caches", func(t *testing.T) {
		contentType = "application/json"
		doc = mustJSON(t, map[string]any{
			"client_id":     id,
			"client_name":   "Fetched Client",
			"redirect_uris": []string{"https://client.example/callback"},
		})

		got, err := c.Fetch(context.Background(), id)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name != "Fetched Client" {
			t.Errorf("Name = %q", got.Name)
		}

		// Serve something invalid; a cached hit must not notice.
		doc = []byte("not json")
		again, err := c.Fetch(context.Background(), id)
		if err != nil {
			t.Fatalf("the cached entry was not used: %v", err)
		}
		if again.Name != "Fetched Client" {
			t.Errorf("cached Name = %q", again.Name)
		}
	})

	t.Run("refuses a document over the size limit", func(t *testing.T) {
		fresh := newCIMD(false)
		fresh.http.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		contentType = "application/json"
		doc = []byte(`{"client_id":"` + id + `","client_name":"` +
			strings.Repeat("x", cimdMaxBody) + `","redirect_uris":["https://client.example/callback"]}`)

		if _, err := fresh.Fetch(context.Background(), id); err == nil {
			t.Fatal("accepted a document over the size limit")
		}
	})

	t.Run("refuses a non-JSON content type", func(t *testing.T) {
		fresh := newCIMD(false)
		fresh.http.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		contentType = "text/html"
		doc = mustJSON(t, map[string]any{"client_id": id, "redirect_uris": []string{"https://client.example/callback"}})

		if _, err := fresh.Fetch(context.Background(), id); err == nil {
			t.Fatal("accepted a document served as HTML")
		}
	})
}

// TestCIMDDisabledByDefault: the capability is a network capability, so it has
// to be turned on deliberately, and the advertised metadata must agree.
func TestCIMDDisabledByDefault(t *testing.T) {
	h := newHarness(t)

	if h.srv.cfg.CIMDEnabled {
		t.Error("CIMD is on without being asked for")
	}

	_, err := h.srv.resolveClient(t.Context(), "https://client.example/mcp")
	if err == nil {
		t.Error("an https client_id resolved while CIMD is disabled")
	}

	resp := h.get(h.proxy.URL + "/.well-known/oauth-authorization-server")
	defer resp.Body.Close()
	var meta map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta["client_id_metadata_document_supported"] != false {
		t.Errorf("metadata advertises %v, want false", meta["client_id_metadata_document_supported"])
	}
}

func TestLooksLikeCIMD(t *testing.T) {
	if !looksLikeCIMD("https://client.example/mcp") {
		t.Error("an https client_id was not recognised")
	}
	// Registered ids are base64url and must keep taking the database path.
	if looksLikeCIMD(newSecret()) {
		t.Error("a registered client id was mistaken for a metadata document URL")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
