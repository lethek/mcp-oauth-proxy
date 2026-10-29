package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// /admin manages the targets stored in the database. It runs its own login with
// its own cookie, so a settings session (which any user can hold) is never an
// admin one, and the cookie is short because the groups claim is read only at
// sign-in: removing someone from an admin group takes effect within the cookie's
// life. No prompt=login or max_age is sent, so this lifetime is the only
// freshness bound.
const (
	adminCookie     = "mcp_admin"
	adminSessionTTL = 30 * time.Minute
)

// adminSession is what the sealed cookie carries. CSRF is a secret that never
// reaches the page; forms carry tokens derived from it.
type adminSession struct {
	Subject string `json:"sub"`
	CSRF    string `json:"csrf"`
	Expires int64  `json:"exp"`
}

func (s *Server) adminRedirectURI() string { return s.cfg.PublicURL + "/admin/callback" }

// isAdmin applies the two lists in the environment, at sign-in only.
func (s *Server) isAdmin(id UserIdentity) bool {
	if slices.Contains(s.cfg.AdminSubjects, id.Subject) {
		return true
	}
	for _, g := range id.Groups {
		if slices.Contains(s.cfg.AdminGroups, g) {
			return true
		}
	}
	return false
}

func (s *Server) sealAdminSession(sess adminSession) (string, error) {
	raw, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	return s.sealer.sealString(purposeAdminSession, raw)
}

// adminFrom returns the signed-in admin. As with the settings cookie, anything
// that does not open is treated as absent and sends the person back to sign in.
func (s *Server) adminFrom(r *http.Request) (adminSession, bool) {
	c, err := r.Cookie(s.cookieName(adminCookie))
	if err != nil {
		return adminSession{}, false
	}
	raw, err := s.sealer.openString(purposeAdminSession, c.Value)
	if err != nil {
		return adminSession{}, false
	}
	var sess adminSession
	if json.Unmarshal(raw, &sess) != nil || sess.Subject == "" || sess.CSRF == "" || time.Now().Unix() > sess.Expires {
		return adminSession{}, false
	}
	return sess, true
}

// token is the CSRF token for one form: the form's kind and the row it acts on,
// keyed by the session's secret. A token from one form or session is no use on
// another, and the key fields cannot be altered without invalidating it.
func (a adminSession) token(form string, key TargetKey) string {
	m := hmac.New(sha256.New, []byte(a.CSRF))
	for _, p := range []string{form, key.Name, key.RowID, strconv.FormatInt(key.Revision, 10)} {
		m.Write([]byte(strconv.Quote(p)))
		m.Write([]byte{' '})
	}
	return hex.EncodeToString(m.Sum(nil))
}

func renderAdminError(w http.ResponseWriter, status int, heading, message string) {
	writePage(w, status, errorTemplate, "'self'", errorView{
		Heading: heading, Message: message, BackHref: "/admin", BackLabel: "Back to servers",
	})
}

// ---------- login ----------

func (s *Server) handleAdminCallback(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.finishLogin(r, flowKindAdmin, s.adminRedirectURI(), func(status int, heading, message string) {
		renderAdminError(w, status, heading, message)
	})
	if !ok {
		return
	}
	if !s.isAdmin(identity) {
		slog.Warn("admin: sign-in refused, not an administrator", "subject", identity.Subject)
		renderError(w, http.StatusForbidden, "Not an administrator", "This account is not allowed to manage servers.")
		return
	}
	sess := adminSession{Subject: identity.Subject, CSRF: newSecret(), Expires: time.Now().Add(adminSessionTTL).Unix()}
	sealed, err := s.sealAdminSession(sess)
	if err != nil {
		slog.Error("admin: could not seal the session", "err", err)
		renderAdminError(w, http.StatusInternalServerError, "Something went wrong", "Your session could not be started. Try again.")
		return
	}
	s.setCookie(w, adminCookie, sealed, int(adminSessionTTL.Seconds()))
	slog.Info("admin: signed in", "subject", identity.Subject)
	http.Redirect(w, r, s.cfg.PublicURL+"/admin", http.StatusFound)
}

// adminGET returns the session for a page view, starting the login when there
// is none.
func (s *Server) adminGET(w http.ResponseWriter, r *http.Request) (adminSession, bool) {
	sess, ok := s.adminFrom(r)
	if !ok {
		s.startLogin(w, r, flowKindAdmin, s.adminRedirectURI())
	}
	return sess, ok
}

// adminPOST gates every state-changing request: same origin, a live admin
// session, and the CSRF token for this form and row. The key comes from the form,
// and the token covers it.
func (s *Server) adminPOST(w http.ResponseWriter, r *http.Request, form, name string) (adminSession, TargetKey, bool) {
	if !s.sameOrigin(r) {
		slog.Warn("admin: cross-origin submission refused", "origin", r.Header.Get("Origin"))
		renderAdminError(w, http.StatusForbidden, "Request blocked", "This request did not come from the admin page.")
		return adminSession{}, TargetKey{}, false
	}
	sess, ok := s.adminFrom(r)
	if !ok {
		http.Redirect(w, r, s.cfg.PublicURL+"/admin", http.StatusFound)
		return adminSession{}, TargetKey{}, false
	}
	if err := r.ParseForm(); err != nil {
		renderAdminError(w, http.StatusBadRequest, "Could not read the form", "The form submission was malformed. Go back and try again.")
		return adminSession{}, TargetKey{}, false
	}
	key := TargetKey{Name: name, RowID: r.PostForm.Get("row_id")}
	if rev := r.PostForm.Get("revision"); rev != "" {
		n, err := strconv.ParseInt(rev, 10, 64)
		if err != nil {
			renderAdminError(w, http.StatusBadRequest, "Could not read the form", "The form submission was malformed. Go back and try again.")
			return adminSession{}, TargetKey{}, false
		}
		key.Revision = n
	}
	if !hmac.Equal([]byte(r.PostForm.Get("csrf")), []byte(sess.token(form, key))) {
		slog.Warn("admin: submission with a missing or wrong token refused", "subject", sess.Subject)
		renderAdminError(w, http.StatusForbidden, "Request blocked", "This form has expired or did not come from the admin page. Go back and reload it.")
		return adminSession{}, TargetKey{}, false
	}
	return sess, key, true
}

// handleAdminLogout ends the admin session in this browser. The session is
// stateless, so a copy of the cookie stays valid until it expires. Without a
// session there is nothing to check a token against, so the cookie is cleared
// and the person is sent back to sign in.
func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminFrom(r); !ok && s.sameOrigin(r) {
		s.setCookie(w, adminCookie, "", -1)
		http.Redirect(w, r, s.cfg.PublicURL+"/admin", http.StatusFound)
		return
	}
	sess, _, ok := s.adminPOST(w, r, "logout", "")
	if !ok {
		return
	}
	s.setCookie(w, adminCookie, "", -1)
	slog.Info("admin: signed out", "subject", sess.Subject, "operation", "logout")
	http.Redirect(w, r, s.cfg.PublicURL+"/admin", http.StatusFound)
}

// ---------- list ----------

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminGET(w, r)
	if !ok {
		return
	}
	rows, _, err := s.store.LoadAdminTargets(r.Context())
	if err != nil {
		slog.Error("admin: could not list targets", "err", err)
		renderAdminError(w, http.StatusInternalServerError, "Something went wrong", "The servers could not be read. Try again in a moment.")
		return
	}
	snap := s.reg.Load()
	view := adminListView{Subject: sess.Subject, Logout: sess.token("logout", TargetKey{}), Ignored: snap.ignored}
	switch r.URL.Query().Get("notice") {
	case "created":
		view.Notice = "Server added."
	case "updated":
		view.Notice = "Server updated."
	case "removed":
		view.Notice = "Server removed."
	}
	for _, e := range snap.entries {
		if e.Target.Source != SourceAdmin {
			view.Config = append(view.Config, adminRow{Name: e.Target.Name, Display: e.Target.DisplayName, Host: upstreamHost(e.Target), Mode: string(e.Target.Mode)})
		}
	}
	for _, a := range rows {
		t := a.Target
		row := adminRow{
			Name: t.Name, Display: t.DisplayName, Host: upstreamHost(t), Mode: string(t.Mode),
			UpdatedAt: a.UpdatedAt.UTC().Format("2006-01-02 15:04 MST"), UpdatedBy: a.UpdatedBy,
		}
		// Not served here means the row is unusable, or this replica has not
		// caught up with it yet.
		if e := snap.find(t.Name); e != nil && e.Stamp == a.StoredStamp {
			row.Served = true
		}
		if t.Mode == CredPerUser {
			if _, row.Enrolments, err = s.store.TargetUsage(r.Context(), t.Name, a.StoredStamp); err != nil {
				slog.Error("admin: could not count enrolments", "err", err)
			}
		}
		view.Admin = append(view.Admin, row)
	}
	writePage(w, http.StatusOK, adminListTemplate, "'self'", view)
}

// ---------- forms ----------

// adminFields are the values a person typed, kept as text so a form that failed
// can be shown again exactly as it was. Static values are deliberately not here:
// they are write-only and never go back into a page.
type adminFields struct {
	Display    string
	Upstream   string
	Mode       string
	UserFields string
	Groups     string
}

func fieldsOf(t Target) adminFields {
	f := adminFields{Display: t.DisplayName, Upstream: t.UpstreamMCP, Mode: string(t.Mode), Groups: strings.Join(t.AllowedGroups, ", ")}
	if len(t.UserFields) > 0 {
		raw, _ := json.MarshalIndent(t.UserFields, "", "  ")
		f.UserFields = string(raw)
	}
	return f
}

func fieldsPosted(r *http.Request) adminFields {
	p := r.PostForm
	return adminFields{Display: p.Get("display_name"), Upstream: p.Get("upstream_mcp"), Mode: p.Get("mode"),
		UserFields: p.Get("user_fields"), Groups: p.Get("allowed_groups")}
}

// parseTarget builds the target a form describes. Fields that do not belong to
// the chosen mode are ignored, so switching mode does not leave an old field
// failing validation. supplied reports whether a static value was entered. The
// message, when not empty, is for the person and never repeats a static value.
func parseTarget(name string, f adminFields, staticRaw string) (t Target, supplied bool, msg string) {
	t = Target{Name: name, DisplayName: f.Display, UpstreamMCP: f.Upstream, Mode: CredentialMode(f.Mode), Source: SourceAdmin}
	for _, g := range strings.Split(f.Groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			t.AllowedGroups = append(t.AllowedGroups, g)
		}
	}
	switch t.Mode {
	case CredStatic:
		if strings.TrimSpace(staticRaw) != "" {
			var err error
			if t.StaticHeaders, err = parseStaticHeaders("Static headers", staticRaw); err != nil {
				return t, false, "Static headers: write one header per line as Name: Value, each with a value."
			}
			supplied = true
		}
	case CredPerUser:
		var err error
		if t.UserFields, err = parseUserHeaderFields(f.UserFields); err != nil {
			return t, false, "User fields: " + err.Error()
		}
	}
	return t, supplied, ""
}

// formMessage rewrites a validation error for the form. validateTarget words its
// errors for the environment, so the variable names become field names. A
// rejected static header name is replaced outright, because it is taken from the
// text of a secret.
func formMessage(err error, name string) string {
	p := envPrefix(name)
	msg := err.Error()
	if strings.Contains(msg, p+"STATIC_HEADERS: ") && strings.Contains(msg, "is not a valid header name") {
		return "Static headers: a header name is not valid. Write one header per line as Name: Value."
	}
	return strings.NewReplacer(
		"TARGETS: ", "Name: ",
		p+"DISPLAY_NAME", "Display name",
		p+"CREDENTIAL_MODE", "Credential mode",
		p+"STATIC_HEADERS", "Static headers",
		p+"USER_HEADERS", "User fields",
		p+"ALLOWED_GROUPS", "Allowed groups",
	).Replace(msg)
}

// saveError turns a failed save into text for the form and a status, or reports
// that the failure is not one the person can fix.
func saveError(err error, name string) (msg string, status int) {
	var invalid *InvalidTargetError
	switch {
	case errors.As(err, &invalid):
		return formMessage(invalid, name), http.StatusBadRequest
	case errors.Is(err, ErrStaticValueRequired):
		return "Static headers: enter the static value again, because the URL or mode changed.", http.StatusBadRequest
	case errors.Is(err, ErrTargetExists):
		return "A server with that name already exists.", http.StatusConflict
	}
	return "", http.StatusInternalServerError
}

// rebuildNow makes this replica serve a change straight away. Other replicas
// follow within the polling interval. A failure leaves the old snapshot, which
// the poller corrects.
func (s *Server) rebuildNow(r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), rebuildTimeout)
	defer cancel()
	if err := s.reg.Rebuild(ctx); err != nil {
		slog.Warn("admin: rebuilding after a change failed; the poller will retry", "err", err)
	}
}

// audit logs one line per change. Field names only: the values include secrets.
func audit(sess adminSession, op, name string, fields []string) {
	slog.Info("admin: target changed", "subject", sess.Subject, "operation", op, "target", name, "fields", fields)
}

// changedFields names what differs between two definitions.
func changedFields(old, t Target, staticSupplied bool) []string {
	var out []string
	if old.DisplayName != t.DisplayName {
		out = append(out, "display_name")
	}
	if old.UpstreamMCP != t.UpstreamMCP {
		out = append(out, "upstream_mcp")
	}
	if old.Mode != t.Mode {
		out = append(out, "mode")
	}
	if !slices.Equal(old.UserFields, t.UserFields) {
		out = append(out, "user_fields")
	}
	if !slices.Equal(old.AllowedGroups, t.AllowedGroups) && (len(old.AllowedGroups)+len(t.AllowedGroups)) > 0 {
		out = append(out, "allowed_groups")
	}
	if staticSupplied {
		out = append(out, "static_value")
	}
	return out
}

func editView(sess adminSession, key TargetKey, isNew bool, f adminFields, hasStatic bool, msg string) adminEditView {
	v := adminEditView{
		New: isNew, Name: key.Name, RowID: key.RowID, Revision: key.Revision, Fields: f, HasStatic: hasStatic, Error: msg,
		Action: "/admin/targets/new",
	}
	if isNew {
		v.CSRF = sess.token("new", key)
	} else {
		v.Action = "/admin/targets/" + key.Name + "/edit"
		v.CSRF = sess.token("edit", key)
	}
	return v
}

func (s *Server) handleAdminNew(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminGET(w, r)
	if !ok {
		return
	}
	writePage(w, http.StatusOK, adminEditTemplate, "'self'",
		editView(sess, TargetKey{}, true, adminFields{Mode: string(CredProviderToken)}, false, ""))
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	sess, key, ok := s.adminPOST(w, r, "new", "")
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	f := fieldsPosted(r)
	again := func(status int, msg string) {
		v := editView(sess, key, true, f, false, msg)
		v.Name = name
		writePage(w, status, adminEditTemplate, "'self'", v)
	}
	t, supplied, msg := parseTarget(name, f, r.PostForm.Get("static_headers"))
	if msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}
	// A name is taken by a config target too. The registry would let the new
	// target outrank it, which is for a config target added after the fact, not
	// for displacing one that is serving now.
	if s.reg.Load().configHolds(name) {
		again(http.StatusConflict, "A server from the configuration already uses that name.")
		return
	}
	_, err := s.store.CreateTarget(r.Context(), t, sess.Subject)
	if err != nil {
		msg, status := saveError(err, name)
		if msg == "" {
			slog.Error("admin: could not create a target", "err", err, "target", name)
			renderAdminError(w, status, "Something went wrong", "The server could not be saved. Try again.")
			return
		}
		again(status, msg)
		return
	}
	audit(sess, "create", name, changedFields(Target{}, normaliseAdminTarget(t), supplied))
	s.rebuildNow(r)
	http.Redirect(w, r, s.cfg.PublicURL+"/admin?notice=created", http.StatusFound)
}

// currentRow loads the row a form was rendered from. It answers the request
// itself when the row is gone or has moved on.
func (s *Server) currentRow(w http.ResponseWriter, r *http.Request, key TargetKey) (AdminTarget, bool) {
	cur, err := s.store.GetTarget(r.Context(), key.Name)
	if errors.Is(err, ErrNotFound) {
		renderAdminError(w, http.StatusNotFound, "No such server", "There is no server by that name managed here.")
		return cur, false
	}
	if err != nil {
		slog.Error("admin: could not read a target", "err", err, "target", key.Name)
		renderAdminError(w, http.StatusInternalServerError, "Something went wrong", "The server could not be read. Try again in a moment.")
		return cur, false
	}
	// Editing is checked against the row again inside the transaction. This is
	// for the page: it must not show consequences for a row the form is not about.
	if r.Method == http.MethodPost && (cur.RowID != key.RowID || cur.Revision != key.Revision) {
		changedPage(w)
		return cur, false
	}
	return cur, true
}

func changedPage(w http.ResponseWriter) {
	renderAdminError(w, http.StatusConflict, "Server changed",
		"This server was changed or removed after the page was loaded. Go back and reload it.")
}

func (s *Server) handleAdminEdit(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminGET(w, r)
	if !ok {
		return
	}
	cur, ok := s.currentRow(w, r, TargetKey{Name: r.PathValue("name")})
	if !ok {
		return
	}
	key := TargetKey{Name: cur.Target.Name, RowID: cur.RowID, Revision: cur.Revision}
	writePage(w, http.StatusOK, adminEditTemplate, "'self'",
		editView(sess, key, false, fieldsOf(cur.Target), cur.Target.Mode == CredStatic, ""))
}

func (s *Server) handleAdminUpdate(w http.ResponseWriter, r *http.Request) {
	sess, key, ok := s.adminPOST(w, r, "edit", r.PathValue("name"))
	if !ok {
		return
	}
	cur, ok := s.currentRow(w, r, key)
	if !ok {
		return
	}
	f := fieldsPosted(r)
	again := func(status int, msg string) {
		writePage(w, status, adminEditTemplate, "'self'",
			editView(sess, key, false, f, cur.Target.Mode == CredStatic, msg))
	}
	t, supplied, msg := parseTarget(key.Name, f, r.PostForm.Get("static_headers"))
	if msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}

	// A replacement ends every session and saved credential, so it goes through
	// a confirmation page first. The same test the store applies decides it.
	probe := normaliseAdminTarget(t)
	probe.Generation = cur.Target.Generation
	if probe.Stamp() != cur.StoredStamp {
		// Refuse what the store would refuse before asking for a typed name. The
		// static value is re-entered on the confirm page, so a stand-in keeps its
		// absence from failing this check.
		check := probe
		if check.Mode == CredStatic && len(check.StaticHeaders) == 0 {
			check.StaticHeaders = map[string]string{"X-Check": "x"}
		}
		if err := s.store.checkAdminTarget(check); err != nil {
			again(http.StatusBadRequest, formMessage(err, key.Name))
			return
		}
		s.renderConfirm(w, r, http.StatusOK, sess, "confirm", cur, f, "")
		return
	}
	s.applyUpdate(w, r, sess, key, cur, t, supplied, again)
}

// applyUpdate saves an edit and answers the request. again redraws the form the
// edit came from, for refusals the person can fix.
func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request, sess adminSession, key TargetKey, cur AdminTarget, t Target, supplied bool, again func(status int, msg string)) {
	_, err := s.store.UpdateTarget(r.Context(), key, t, sess.Subject)
	if errors.Is(err, ErrTargetChanged) {
		changedPage(w)
		return
	}
	if err != nil {
		msg, status := saveError(err, key.Name)
		if msg == "" {
			slog.Error("admin: could not update a target", "err", err, "target", key.Name)
			renderAdminError(w, status, "Something went wrong", "The server could not be saved. Try again.")
			return
		}
		again(status, msg)
		return
	}
	audit(sess, "update", key.Name, changedFields(cur.Target, normaliseAdminTarget(t), supplied))
	s.rebuildNow(r)
	http.Redirect(w, r, s.cfg.PublicURL+"/admin?notice=updated", http.StatusFound)
}

// ---------- confirmation ----------

// renderConfirm shows what a replacement or removal will end. kind is the form
// that the page posts: "confirm" for a replacement, "remove" for a removal.
func (s *Server) renderConfirm(w http.ResponseWriter, r *http.Request, status int, sess adminSession, kind string, cur AdminTarget, f adminFields, msg string) {
	sessions, enrolments, err := s.store.TargetUsage(r.Context(), cur.Target.Name, cur.StoredStamp)
	if err != nil {
		slog.Error("admin: could not count what a change would end", "err", err, "target", cur.Target.Name)
		renderAdminError(w, http.StatusInternalServerError, "Something went wrong", "The consequences could not be worked out. Try again in a moment.")
		return
	}
	key := TargetKey{Name: cur.Target.Name, RowID: cur.RowID, Revision: cur.Revision}
	writePage(w, status, adminConfirmTemplate, "'self'", adminConfirmView{
		Remove: kind == "remove", TakeOver: kind == "remove" && s.reg.Load().wasIgnored(key.Name), Name: key.Name, Display: cur.Target.DisplayName,
		Sessions: sessions, Enrolments: enrolments,
		Action: "/admin/targets/" + key.Name + "/" + kind, CSRF: sess.token(kind, key),
		RowID: key.RowID, Revision: key.Revision, Fields: f,
		NeedStatic: kind == "confirm" && f.Mode == string(CredStatic), Error: msg,
	})
}

func (s *Server) handleAdminConfirm(w http.ResponseWriter, r *http.Request) {
	sess, key, ok := s.adminPOST(w, r, "confirm", r.PathValue("name"))
	if !ok {
		return
	}
	cur, ok := s.currentRow(w, r, key)
	if !ok {
		return
	}
	f := fieldsPosted(r)
	again := func(status int, msg string) { s.renderConfirm(w, r, status, sess, "confirm", cur, f, msg) }
	if r.PostForm.Get("confirm_name") != key.Name {
		again(http.StatusBadRequest, "Type the server's name exactly as shown to confirm.")
		return
	}
	t, supplied, msg := parseTarget(key.Name, f, r.PostForm.Get("static_headers"))
	if msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}
	s.applyUpdate(w, r, sess, key, cur, t, supplied, again)
}

func (s *Server) handleAdminRemoveForm(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminGET(w, r)
	if !ok {
		return
	}
	cur, ok := s.currentRow(w, r, TargetKey{Name: r.PathValue("name")})
	if !ok {
		return
	}
	s.renderConfirm(w, r, http.StatusOK, sess, "remove", cur, adminFields{}, "")
}

func (s *Server) handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	sess, key, ok := s.adminPOST(w, r, "remove", r.PathValue("name"))
	if !ok {
		return
	}
	cur, ok := s.currentRow(w, r, key)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm_name") != key.Name {
		s.renderConfirm(w, r, http.StatusBadRequest, sess, "remove", cur, adminFields{}, "Type the server's name exactly as shown to confirm.")
		return
	}
	err := s.store.DeleteTarget(r.Context(), key)
	if errors.Is(err, ErrTargetChanged) {
		changedPage(w)
		return
	}
	if err != nil {
		slog.Error("admin: could not remove a target", "err", err, "target", key.Name)
		renderAdminError(w, http.StatusInternalServerError, "Something went wrong", "The server could not be removed. Try again.")
		return
	}
	audit(sess, "remove", key.Name, nil)
	s.rebuildNow(r)
	http.Redirect(w, r, s.cfg.PublicURL+"/admin?notice=removed", http.StatusFound)
}

// ---------- rendering ----------

type adminRow struct {
	Name, Display, Host, Mode string
	UpdatedAt, UpdatedBy      string
	Served                    bool
	Enrolments                int
}

type adminListView struct {
	Subject string
	Logout  string // CSRF token for the sign-out form
	Notice  string
	Admin   []adminRow
	Config  []adminRow
	Ignored []ignoredTarget
}

type adminEditView struct {
	New       bool
	Name      string
	RowID     string
	Revision  int64
	CSRF      string
	Action    string
	Fields    adminFields
	HasStatic bool
	Error     string
}

type adminConfirmView struct {
	Remove     bool
	Name       string
	Display    string
	Sessions   int
	Enrolments int
	Action     string
	CSRF       string
	RowID      string
	Revision   int64
	Fields     adminFields
	NeedStatic bool
	Error      string
	// TakeOver is set when a config target of the same name is waiting.
	TakeOver bool
}

var (
	adminListTemplate    = newPage("admin_list")
	adminEditTemplate    = newPage("admin_edit")
	adminConfirmTemplate = newPage("admin_confirm")
)
