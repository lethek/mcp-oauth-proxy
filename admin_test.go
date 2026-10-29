package main

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// adminUser42 makes the harness's signed-in user (sub user-42) an admin.
func adminUser42(cfg *Config, upstreamURL string) []Target {
	adminOn(cfg, upstreamURL)
	cfg.AdminSubjects = []string{"user-42"}
	return twoTargets(cfg, upstreamURL)
}

func adminUser42PerUser(cfg *Config, upstreamURL string) []Target {
	adminOn(cfg, upstreamURL)
	cfg.AdminSubjects = []string{"user-42"}
	return perUserTargets(cfg, upstreamURL)
}

// signInAdmin walks the admin login and returns the last response, which is the
// callback's.
func (h *harness) signInAdmin() *http.Response {
	h.t.Helper()
	start := h.get(h.proxy.URL + "/admin")
	start.Body.Close()
	if start.StatusCode != http.StatusFound {
		h.t.Fatalf("GET /admin without a session: status %d, want a redirect to sign in", start.StatusCode)
	}
	toProvider := h.get(start.Header.Get("Location"))
	toProvider.Body.Close()
	done := h.get(toProvider.Header.Get("Location"))
	done.Body.Close()
	return done
}

func (h *harness) mustSignInAdmin() {
	h.t.Helper()
	if done := h.signInAdmin(); done.StatusCode != http.StatusFound {
		h.t.Fatalf("admin sign-in: status %d, want 302", done.StatusCode)
	}
}

// do sends one request as the browser and returns the status and body.
func (h *harness) do(method, path string, form url.Values, header map[string]string) (int, string, http.Header) {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, h.proxy.URL+path, body)
	if err != nil {
		h.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), resp.Header
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// hiddenFields reads the hidden inputs of a rendered form, which is where the
// CSRF token and the row key travel.
func hiddenFields(body string) url.Values {
	out := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(body, -1) {
		out.Set(m[1], html.UnescapeString(m[2]))
	}
	return out
}

// formFor loads a page and returns its hidden fields.
func (h *harness) formFor(path string) url.Values {
	h.t.Helper()
	status, body, _ := h.do("GET", path, nil, nil)
	if status != http.StatusOK {
		h.t.Fatalf("GET %s: status %d", path, status)
	}
	return hiddenFields(body)
}

func merge(a url.Values, b url.Values) url.Values {
	for k, v := range b {
		a[k] = v
	}
	return a
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLogs(t *testing.T) *syncBuf {
	t.Helper()
	prev := slog.Default()
	buf := &syncBuf{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func (h *harness) proxyURL() *url.URL {
	u, err := url.Parse(h.proxy.URL)
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) cookieValue(name string) string {
	for _, c := range h.client.Jar.Cookies(h.proxyURL()) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (h *harness) setCookie(name, value string) {
	h.client.Jar.SetCookies(h.proxyURL(), []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

func (h *harness) createTargetForm(name, path, mode, static string) url.Values {
	return merge(h.formFor("/admin/targets/new"), url.Values{
		"name": {name}, "display_name": {"Server " + name}, "upstream_mcp": {h.provider.URL + path},
		"mode": {mode}, "static_headers": {static},
	})
}

// ---------- identity ----------

func TestAdminSubjectSignsIn(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	done := h.signInAdmin()
	if done.StatusCode != http.StatusFound || done.Header.Get("Location") != h.proxy.URL+"/admin" {
		t.Fatalf("callback: %d to %q, want a redirect to /admin", done.StatusCode, done.Header.Get("Location"))
	}
	var lifetime int
	for _, c := range done.Cookies() {
		if c.Name == adminCookie {
			lifetime = c.MaxAge
		}
	}
	if lifetime != int(adminSessionTTL.Seconds()) {
		t.Errorf("admin cookie Max-Age = %d, want %d", lifetime, int(adminSessionTTL.Seconds()))
	}
	if status, body, _ := h.do("GET", "/admin", nil, nil); status != http.StatusOK || !strings.Contains(body, "Servers") {
		t.Errorf("GET /admin signed in: status %d", status)
	}
}

func TestAdminGroupSignsInAndOthersAreRefused(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.srv.cfg.AdminSubjects = nil
	h.srv.cfg.AdminGroups = []string{"ops"}

	h.setGroups("users")
	done := h.signInAdmin()
	if done.StatusCode != http.StatusForbidden {
		t.Fatalf("a non-member signed in with status %d, want 403", done.StatusCode)
	}
	if h.cookieValue(adminCookie) != "" {
		t.Error("a refused sign-in still set the admin cookie")
	}

	h.setGroups("users", "ops")
	if done := h.signInAdmin(); done.StatusCode != http.StatusFound {
		t.Fatalf("a group member got status %d, want 302", done.StatusCode)
	}
}

func TestNonAdminSubjectIsRefused(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.srv.cfg.AdminSubjects = []string{"someone-else"}
	if done := h.signInAdmin(); done.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", done.StatusCode)
	}
	if status, _, _ := h.do("GET", "/admin", nil, nil); status != http.StatusFound {
		t.Errorf("GET /admin after a refusal: status %d, want a redirect to sign in", status)
	}
}

// The two cookies hold the same kind of value under different purposes, so each
// page must refuse the other's.
func TestSettingsAndAdminCookiesAreNotInterchangeable(t *testing.T) {
	h := newHarnessWith(t, adminUser42PerUser)
	h.signIntoSettings()
	settings := h.cookieValue(settingsCookie)
	if settings == "" {
		t.Fatal("no settings cookie after signing in")
	}

	h.setCookie(adminCookie, settings)
	status, _, header := h.do("GET", "/admin", nil, nil)
	if status != http.StatusFound || !strings.Contains(header.Get("Location"), "/login/oauth/authorize") {
		t.Errorf("a settings cookie at /admin: status %d to %q, want a fresh sign-in", status, header.Get("Location"))
	}

	h.mustSignInAdmin()
	h.setCookie(settingsCookie, h.cookieValue(adminCookie))
	status, _, header = h.do("GET", "/settings", nil, nil)
	if status != http.StatusFound || !strings.Contains(header.Get("Location"), "/login/oauth/authorize") {
		t.Errorf("an admin cookie at /settings: status %d to %q, want a fresh sign-in", status, header.Get("Location"))
	}
}

func TestAdminCookieExpires(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	seal := func(expires time.Time) string {
		v, err := h.srv.sealAdminSession(adminSession{Subject: "user-42", CSRF: "k", Expires: expires.Unix()})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	h.setCookie(adminCookie, seal(time.Now().Add(time.Minute)))
	if status, _, _ := h.do("GET", "/admin", nil, nil); status != http.StatusOK {
		t.Fatalf("a live cookie: status %d, want 200", status)
	}
	h.setCookie(adminCookie, seal(time.Now().Add(-time.Second)))
	if status, _, _ := h.do("GET", "/admin", nil, nil); status != http.StatusFound {
		t.Errorf("an expired cookie: status %d, want a redirect to sign in", status)
	}
}

// A login started for one page must not be redeemable at the other's callback,
// and the failed attempt must not use the flow up.
func TestLoginFlowsAreBoundToTheirPage(t *testing.T) {
	h := newHarnessWith(t, adminUser42PerUser)
	stateOf := func(path string) string {
		resp := h.get(h.proxy.URL + path)
		resp.Body.Close()
		u, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || u.Query().Get("state") == "" {
			t.Fatalf("GET %s: no sign-in redirect (status %d)", path, resp.StatusCode)
		}
		return u.Query().Get("state")
	}
	callback := func(path, state string) int {
		resp := h.get(h.proxy.URL + path + "?code=upstream-code&state=" + state)
		resp.Body.Close()
		return resp.StatusCode
	}

	state := stateOf("/settings")
	if got := callback("/admin/callback", state); got != http.StatusBadRequest {
		t.Errorf("a settings flow at the admin callback: status %d, want 400", got)
	}
	if got := callback("/settings/callback", state); got != http.StatusFound {
		t.Errorf("the settings flow after the refused attempt: status %d, want 302", got)
	}

	state = stateOf("/admin")
	if got := callback("/settings/callback", state); got != http.StatusBadRequest {
		t.Errorf("an admin flow at the settings callback: status %d, want 400", got)
	}
	if got := callback("/admin/callback", state); got != http.StatusFound {
		t.Errorf("the admin flow after the refused attempt: status %d, want 302", got)
	}
}

// ---------- routes ----------

func TestAdminRoutesCoexistWithTargetsNamedAdminAndSettings(t *testing.T) {
	h := newHarnessWith(t, func(cfg *Config, up string) []Target {
		adminOn(cfg, up)
		cfg.AdminSubjects = []string{"user-42"}
		return []Target{
			{Name: "admin", DisplayName: "Admin", UpstreamMCP: up + "/alpha-upstream", Mode: CredProviderToken, Resource: cfg.PublicURL + "/admin/mcp"},
			{Name: "settings", DisplayName: "Settings", UpstreamMCP: up + "/beta-upstream", Mode: CredProviderToken, Resource: cfg.PublicURL + "/settings/mcp"},
		}
	})
	// routes() already ran without panicking. Each page and each target still
	// answers where it should.
	for path, want := range map[string]int{"/admin": http.StatusFound, "/admin/targets/new": http.StatusFound, "/settings": http.StatusOK} {
		if status, _, _ := h.do("GET", path, nil, nil); status != want {
			t.Errorf("GET %s: status %d, want %d", path, status, want)
		}
	}
	for _, path := range []string{"/admin/mcp", "/settings/mcp"} {
		if status, _, _ := h.do("POST", path, nil, nil); status != http.StatusUnauthorized {
			t.Errorf("POST %s: status %d, want 401 from the MCP handler", path, status)
		}
	}
}

func TestAdminRoutesAbsentWhenDisabled(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/admin", "/admin/callback", "/admin/targets/new"} {
		if status, _, _ := h.do("GET", path, nil, nil); status != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, status)
		}
	}
}

// ---------- CSRF ----------

func TestAdminPostsNeedOriginAndToken(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.mustSignInAdmin()
	form := func() url.Values { return h.createTargetForm("gamma", "/alpha-upstream", "provider_token", "") }
	count := func() int { return h.count(`SELECT count(*) FROM targets`) }

	missing := form()
	missing.Del("csrf")
	wrong := form()
	wrong.Set("csrf", "0000")
	// A genuine token, but for a different form: the token covers the form kind.
	otherForm := form()
	otherForm.Set("csrf", h.formFor("/admin/targets/new").Get("csrf"))
	otherForm.Set("revision", "7")

	cases := []struct {
		name   string
		form   url.Values
		header map[string]string
	}{
		{"no token", missing, nil},
		{"wrong token", wrong, nil},
		{"token for another row", otherForm, nil},
		{"cross-origin", form(), map[string]string{"Origin": "https://evil.example"}},
		{"cross-site fetch", form(), map[string]string{"Sec-Fetch-Site": "cross-site"}},
	}
	for _, c := range cases {
		if status, _, _ := h.do("POST", "/admin/targets/new", c.form, c.header); status != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.name, status)
		}
	}
	if n := count(); n != 0 {
		t.Fatalf("%d targets exist after refused submissions", n)
	}

	if status, _, _ := h.do("POST", "/admin/targets/new", form(), nil); status != http.StatusFound {
		t.Errorf("the genuine submission: status %d, want 302", status)
	}
	if n := count(); n != 1 {
		t.Errorf("%d targets after the genuine submission, want 1", n)
	}
}

func TestAdminPostWithoutSessionGoesToSignIn(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	if status, _, _ := h.do("POST", "/admin/targets/new", url.Values{"name": {"x"}}, nil); status != http.StatusFound {
		t.Errorf("status %d, want a redirect to sign in", status)
	}
	if n := h.count(`SELECT count(*) FROM targets`); n != 0 {
		t.Errorf("%d targets created without a session", n)
	}
}

func TestCSRFTokenIsBoundToSessionFormAndRow(t *testing.T) {
	a, b := adminSession{CSRF: "a"}, adminSession{CSRF: "b"}
	key := TargetKey{Name: "x", RowID: "r", Revision: 1}
	base := a.token("edit", key)
	for name, other := range map[string]string{
		"session":  b.token("edit", key),
		"form":     a.token("remove", key),
		"name":     a.token("edit", TargetKey{Name: "y", RowID: "r", Revision: 1}),
		"row":      a.token("edit", TargetKey{Name: "x", RowID: "s", Revision: 1}),
		"revision": a.token("edit", TargetKey{Name: "x", RowID: "r", Revision: 2}),
	} {
		if other == base {
			t.Errorf("a token is unchanged when the %s differs", name)
		}
	}
}

// ---------- changes ----------

func TestStaleRevisionIsRefused(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	row := h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()
	h.mustSignInAdmin()

	form := h.formFor("/admin/targets/gamma/edit")
	renamed := h.adminTarget("gamma", "/alpha-upstream")
	renamed.DisplayName = "Changed elsewhere"
	if _, err := h.srv.store.UpdateTarget(t.Context(), TargetKey{"gamma", row.RowID, row.Revision}, renamed, "root"); err != nil {
		t.Fatal(err)
	}

	status, _, _ := h.do("POST", "/admin/targets/gamma/edit", merge(form, url.Values{
		"display_name": {"Stale"}, "upstream_mcp": {h.provider.URL + "/alpha-upstream"}, "mode": {"provider_token"},
	}), nil)
	if status != http.StatusConflict {
		t.Errorf("status %d, want 409", status)
	}
	got, err := h.srv.store.GetTarget(t.Context(), "gamma")
	if err != nil || got.Target.DisplayName != "Changed elsewhere" {
		t.Errorf("the row is %q (%v), want the other edit kept", got.Target.DisplayName, err)
	}
}

func TestReplacementAndRemovalNeedTheTypedName(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.createAdmin(h.adminTarget("gamma", "/alpha-upstream"))
	h.rebuild()
	h.mustSignInAdmin()

	// A session under the current definition, which the page must count.
	clientID := h.register(testRedirect)
	h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")

	edit := merge(h.formFor("/admin/targets/gamma/edit"), url.Values{
		"display_name": {"Gamma"}, "upstream_mcp": {h.provider.URL + "/beta-upstream"}, "mode": {"provider_token"},
	})
	status, body, _ := h.do("POST", "/admin/targets/gamma/edit", edit, nil)
	if status != http.StatusOK || !strings.Contains(body, "confirm_name") || !strings.Contains(body, "1 session ") {
		t.Fatalf("a replacement did not reach the confirmation page with its count: status %d", status)
	}
	if cur, _ := h.srv.store.GetTarget(t.Context(), "gamma"); !strings.HasSuffix(cur.Target.UpstreamMCP, "/alpha-upstream") {
		t.Fatal("the replacement was applied before it was confirmed")
	}

	confirm := hiddenFields(body)
	confirm.Set("confirm_name", "gamm")
	if status, _, _ := h.do("POST", "/admin/targets/gamma/confirm", confirm, nil); status != http.StatusBadRequest {
		t.Errorf("a wrong typed name: status %d, want 400", status)
	}
	confirm.Del("confirm_name")
	if status, _, _ := h.do("POST", "/admin/targets/gamma/confirm", confirm, nil); status != http.StatusBadRequest {
		t.Errorf("no typed name: status %d, want 400", status)
	}
	if cur, _ := h.srv.store.GetTarget(t.Context(), "gamma"); !strings.HasSuffix(cur.Target.UpstreamMCP, "/alpha-upstream") {
		t.Fatal("the replacement was applied without the name")
	}
	confirm.Set("confirm_name", "gamma")
	if status, _, _ := h.do("POST", "/admin/targets/gamma/confirm", confirm, nil); status != http.StatusFound {
		t.Fatalf("the confirmed replacement: status %d, want 302", status)
	}
	if cur, _ := h.srv.store.GetTarget(t.Context(), "gamma"); !strings.HasSuffix(cur.Target.UpstreamMCP, "/beta-upstream") {
		t.Error("the confirmed replacement was not applied")
	}

	// Removal.
	status, body, _ = h.do("GET", "/admin/targets/gamma/remove", nil, nil)
	if status != http.StatusOK || !strings.Contains(body, "0 sessions") {
		t.Fatalf("remove page: status %d, want 200 with counts", status)
	}
	remove := hiddenFields(body)
	remove.Set("confirm_name", "other")
	if status, _, _ := h.do("POST", "/admin/targets/gamma/remove", remove, nil); status != http.StatusBadRequest {
		t.Errorf("a wrong typed name on removal: status %d, want 400", status)
	}
	if _, err := h.srv.store.GetTarget(t.Context(), "gamma"); err != nil {
		t.Fatal("the target was removed without the name")
	}
	remove.Set("confirm_name", "gamma")
	if status, _, _ := h.do("POST", "/admin/targets/gamma/remove", remove, nil); status != http.StatusFound {
		t.Fatalf("the confirmed removal: status %d, want 302", status)
	}
	if _, err := h.srv.store.GetTarget(t.Context(), "gamma"); err == nil {
		t.Error("the target is still stored")
	}
	if h.srv.reg.Load().find("gamma") != nil {
		t.Error("this replica still serves a target it just removed")
	}
}

func TestFormErrorsNameFieldsNotVariables(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.mustSignInAdmin()
	cases := []struct {
		name  string
		edit  func(url.Values)
		wants string
	}{
		{"display", func(f url.Values) { f.Set("display_name", "") }, "Display name is empty"},
		{"static", func(f url.Values) { f.Set("mode", "static") }, "Static headers is required when Credential mode is static"},
		{"per user", func(f url.Values) { f.Set("mode", "per_user") }, "User fields is required when Credential mode is per_user"},
		{"name", func(f url.Values) { f.Set("name", "Bad_Name") }, "Name: "},
		{"reserved", func(f url.Values) { f.Set("name", "admin") }, "reserved name"},
		{"host", func(f url.Values) { f.Set("upstream_mcp", "http://example.org/mcp") }, "Upstream MCP URL: "},
	}
	for _, c := range cases {
		f := h.createTargetForm("gamma", "/alpha-upstream", "provider_token", "")
		c.edit(f)
		status, body, _ := h.do("POST", "/admin/targets/new", f, nil)
		if status != http.StatusBadRequest || !strings.Contains(body, c.wants) {
			t.Errorf("%s: status %d, body lacks %q", c.name, status, c.wants)
		}
		for _, bad := range []string{"TARGET_", "UPSTREAM_", "TARGETS"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: the form error mentions %q", c.name, bad)
			}
		}
	}
	if n := h.count(`SELECT count(*) FROM targets`); n != 0 {
		t.Errorf("%d targets stored by refused forms", n)
	}
}

// A saved target is served by this replica at once, without waiting for the
// poller, and carries the credential the admin entered.
func TestSaveMakesTheTargetServableImmediately(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.mustSignInAdmin()
	if status, _, _ := h.do("POST", "/admin/targets/new", h.createTargetForm("gamma", "/alpha-upstream", "provider_token", ""), nil); status != http.StatusFound {
		t.Fatalf("create: status %d", status)
	}
	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")
	if status, _ := h.mcpStatus("/gamma/mcp", access); status != http.StatusOK {
		t.Errorf("the new target answered %d, want 200", status)
	}
}

// The static credential is write-only: it never appears in a page the admin
// receives, in an error message, or in a log line.
func TestStaticCredentialNeverAppearsInResponsesOrLogs(t *testing.T) {
	logs := captureLogs(t)
	h := newHarnessWith(t, adminUser42)
	h.mustSignInAdmin()

	const first, second, third = "SECRET-ONE-9f3a", "SECRET-TWO-71bc", "SECRET-THREE-c0de"
	var bodies []string
	send := func(method, path string, form url.Values) (int, string) {
		status, body, _ := h.do(method, path, form, nil)
		bodies = append(bodies, body)
		return status, body
	}

	status, _ := send("POST", "/admin/targets/new", h.createTargetForm("gamma", "/alpha-upstream", "static", "Authorization: Bearer "+first))
	if status != http.StatusFound {
		t.Fatalf("create: status %d", status)
	}

	// The credential is used, which is what proves it was stored.
	clientID := h.register(testRedirect)
	access, _ := h.tokensFor(clientID, testRedirect, h.srv.cfg.PublicURL+"/gamma/mcp")
	resp := h.mcpRequest("/gamma/mcp", access)
	var saw struct {
		Authorization string `json:"saw_authorization"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&saw)
	resp.Body.Close()
	if saw.Authorization != "Bearer "+first {
		t.Fatalf("the upstream saw %q, want the stored credential", saw.Authorization)
	}

	send("GET", "/admin", nil)
	send("GET", "/admin/targets/gamma/edit", nil)

	edit := func(f url.Values) url.Values {
		return merge(h.formFor("/admin/targets/gamma/edit"), f)
	}
	// A save that leaves the value alone.
	status, _ = send("POST", "/admin/targets/gamma/edit", edit(url.Values{
		"display_name": {"Gamma again"}, "upstream_mcp": {h.provider.URL + "/alpha-upstream"}, "mode": {"static"},
	}))
	if status != http.StatusFound {
		t.Fatalf("edit keeping the value: status %d", status)
	}

	// A header name taken from the text of a value is refused without echoing it.
	status, body := send("POST", "/admin/targets/gamma/edit", edit(url.Values{
		"display_name": {"Gamma again"}, "upstream_mcp": {h.provider.URL + "/alpha-upstream"}, "mode": {"static"},
		"static_headers": {third + " extra: x"},
	}))
	if status != http.StatusBadRequest || !strings.Contains(body, "header name is not valid") {
		t.Fatalf("a bad header name: status %d", status)
	}
	status, _ = send("POST", "/admin/targets/gamma/edit", edit(url.Values{
		"display_name": {"Gamma again"}, "upstream_mcp": {h.provider.URL + "/alpha-upstream"}, "mode": {"static"},
		"static_headers": {third},
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("a line without a colon: status %d", status)
	}

	// A replacement goes through the confirmation page and asks for the value again.
	status, body = send("POST", "/admin/targets/gamma/edit", edit(url.Values{
		"display_name": {"Gamma again"}, "upstream_mcp": {h.provider.URL + "/beta-upstream"}, "mode": {"static"},
		"static_headers": {"Authorization: Bearer " + second},
	}))
	if status != http.StatusOK || !strings.Contains(body, `name="static_headers"`) {
		t.Fatalf("replacement: status %d, want the confirmation page asking for the value again", status)
	}
	confirm := hiddenFields(body)
	confirm.Set("confirm_name", "gamma")
	if status, _ = send("POST", "/admin/targets/gamma/confirm", confirm); status != http.StatusBadRequest {
		t.Fatalf("a replacement without the value: status %d, want 400", status)
	}
	confirm.Set("static_headers", "Authorization: Bearer "+second)
	if status, _ = send("POST", "/admin/targets/gamma/confirm", confirm); status != http.StatusFound {
		t.Fatalf("the confirmed replacement: status %d", status)
	}
	send("GET", "/admin", nil)
	send("GET", "/admin/targets/gamma/edit", nil)

	all := strings.Join(bodies, "\n") + "\n" + logs.String()
	for _, secret := range []string{first, second, third} {
		if strings.Contains(all, secret) {
			t.Errorf("%s appears in a response or a log line", secret)
		}
	}

	// The audit lines name what changed and who changed it.
	log := logs.String()
	for _, want := range []string{"admin: target changed", "operation=create", "operation=update", "subject=user-42", "static_value"} {
		if !strings.Contains(log, want) {
			t.Errorf("the log has no %q", want)
		}
	}
}

// ---------- pages ----------

func TestListShowsConfigTargetsReadOnlyAndClashes(t *testing.T) {
	h := newHarnessWith(t, adminUser42)
	h.createAdmin(h.adminTarget("alpha", "/beta-upstream"))
	h.rebuild()
	h.mustSignInAdmin()

	status, body, _ := h.do("GET", "/admin", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	for _, want := range []string{"Read only", "name in use by an admin target", "/admin/targets/alpha/edit"} {
		if !strings.Contains(body, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	if strings.Contains(body, "/admin/targets/beta/edit") {
		t.Error("a config target offers an edit link")
	}
}

func TestConsentAndSettingsShowTheUpstreamHost(t *testing.T) {
	rec := httptest.NewRecorder()
	renderConsent(rec, consentView{ClientName: "App", TargetName: "Alpha", TargetHost: "mcp.internal:8443", RedirectURI: "https://c.example/cb"})
	if !strings.Contains(rec.Body.String(), "mcp.internal:8443") {
		t.Error("the consent page does not show the upstream host")
	}

	rec = httptest.NewRecorder()
	renderSettings(rec, settingsView{Subject: "s", Targets: []targetRow{{Name: "a", Display: "Alpha", Host: "mcp.internal:8443"}}})
	if !strings.Contains(rec.Body.String(), "mcp.internal:8443") {
		t.Error("the settings page does not show the upstream host")
	}
}
