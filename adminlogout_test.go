package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The form on the list page is the only way the token reaches the browser, so
// the tests take it from there.
func (h *harness) logoutForm() url.Values {
	h.t.Helper()
	form := h.formFor("/admin")
	if form.Get("csrf") == "" {
		h.t.Fatal("the admin page has no sign-out token")
	}
	return form
}

func TestAdminLogoutClearsTheCookie(t *testing.T) {
	logs := captureLogs(t)
	h := newHarnessWith(t, adminUser42)
	h.mustSignInAdmin()
	form := h.logoutForm()
	if h.cookieValue(adminCookie) == "" {
		t.Fatal("no admin cookie after sign-in")
	}

	status, _, header := h.do("POST", "/admin/logout", form, nil)
	if status != http.StatusFound || header.Get("Location") != h.srv.cfg.PublicURL+"/admin" {
		t.Fatalf("logout: status %d to %q, want 302 to /admin", status, header.Get("Location"))
	}
	if v := h.cookieValue(adminCookie); v != "" {
		t.Errorf("the admin cookie survived logout: %q", v)
	}
	if status, _, _ := h.do("GET", "/admin", nil, nil); status != http.StatusFound {
		t.Errorf("GET /admin after logout: status %d, want a redirect to sign in", status)
	}
	if out := logs.String(); !strings.Contains(out, "operation=logout") || !strings.Contains(out, "subject=user-42") {
		t.Errorf("no audit line for the logout in:\n%s", out)
	}
}

func TestAdminLogoutNeedsOriginAndToken(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.mustSignInAdmin()
	good := h.logoutForm()
	missing := url.Values{}
	wrong := url.Values{"csrf": {"0000"}}
	// A genuine token for another form must not sign anyone out.
	otherForm := url.Values{"csrf": {h.formFor("/admin/targets/new").Get("csrf")}}

	cases := []struct {
		name   string
		form   url.Values
		header map[string]string
	}{
		{"no token", missing, nil},
		{"wrong token", wrong, nil},
		{"token for another form", otherForm, nil},
		{"cross-origin", good, map[string]string{"Origin": "https://evil.example"}},
		{"cross-site fetch", good, map[string]string{"Sec-Fetch-Site": "cross-site"}},
	}
	for _, c := range cases {
		if status, _, _ := h.do("POST", "/admin/logout", c.form, c.header); status != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.name, status)
		}
		if h.cookieValue(adminCookie) == "" {
			t.Fatalf("%s: the refused request cleared the cookie", c.name)
		}
	}
}

func TestAdminLogoutWithoutSessionRedirectsCleanly(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	// A stale cookie that does not open is still removed.
	h.setCookie(adminCookie, "stale")
	status, _, header := h.do("POST", "/admin/logout", url.Values{}, nil)
	if status != http.StatusFound || header.Get("Location") != h.srv.cfg.PublicURL+"/admin" {
		t.Fatalf("status %d to %q, want 302 to /admin", status, header.Get("Location"))
	}
	if v := h.cookieValue(adminCookie); v != "" {
		t.Errorf("the stale cookie survived: %q", v)
	}
	// Cross-origin is still refused without a session.
	if status, _, _ := h.do("POST", "/admin/logout", url.Values{}, map[string]string{"Origin": "https://evil.example"}); status != http.StatusForbidden {
		t.Errorf("cross-origin without a session: status %d, want 403", status)
	}
}

func TestAdminLogoutAbsentWhenDisabled(t *testing.T) {
	h := newHarness(t)
	if status, _, _ := h.do("POST", "/admin/logout", url.Values{}, nil); status != http.StatusNotFound {
		t.Errorf("POST /admin/logout: status %d, want 404", status)
	}
}
