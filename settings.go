package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// The enrolment page needs its own notion of "this browser is this person",
// which the OAuth endpoints do not have: the consent screen is bound to one
// in-flight authorization and means nothing outside it. So /settings runs its
// own authorization-code round trip and keeps the result in a sealed cookie.
const (
	settingsCookie  = "mcp_settings"
	settingsSession = 12 * time.Hour

	// maxCredentialValue bounds one pasted field. Tokens are short; this only
	// stops a row growing without limit.
	maxCredentialValue = 4096
)

// settingsIdentity is what the cookie carries. It is sealed rather than signed,
// so the subject is not readable by the browser holding it, and it is bound to
// its own purpose so no other sealed value can be substituted for it.
type settingsIdentity struct {
	Subject string `json:"sub"`
	Display string `json:"name,omitempty"`
	Expires int64  `json:"exp"`
}

func (s *Server) settingsRedirectURI() string { return s.cfg.PublicURL + "/settings/callback" }

// identityFrom returns the signed-in user, or a zero value when there is no
// usable session. Any failure to open or decode the cookie is treated as absent:
// a tampered or stale cookie should send the user back through the provider,
// not produce an error page.
func (s *Server) identityFrom(r *http.Request) UserIdentity {
	c, err := r.Cookie(s.cookieName(settingsCookie))
	if err != nil {
		return UserIdentity{}
	}
	raw, err := s.sealer.openString(purposeSettingsSession, c.Value)
	if err != nil {
		return UserIdentity{}
	}
	var id settingsIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return UserIdentity{}
	}
	if id.Subject == "" || time.Now().Unix() > id.Expires {
		return UserIdentity{}
	}
	return UserIdentity{Subject: id.Subject, Display: id.Display}
}

func (s *Server) setIdentity(w http.ResponseWriter, identity UserIdentity) error {
	raw, err := json.Marshal(settingsIdentity{
		Subject: identity.Subject,
		Display: identity.Display,
		Expires: time.Now().Add(settingsSession).Unix(),
	})
	if err != nil {
		return err
	}
	sealed, err := s.sealer.sealString(purposeSettingsSession, raw)
	if err != nil {
		return err
	}
	s.setCookie(w, settingsCookie, sealed, int(settingsSession.Seconds()))
	return nil
}

// clearIdentity ends the settings session. Without it the cookie outlives a
// logout at the provider by up to its full lifetime, on the one page that holds
// something worth stealing.
func (s *Server) clearIdentity(w http.ResponseWriter) {
	s.setCookie(w, settingsCookie, "", -1)
}

func (s *Server) handleSettingsLogout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderSettingsError(w, http.StatusForbidden, "Request blocked", "This request did not come from the settings page.")
		return
	}
	s.clearIdentity(w)
	http.Redirect(w, r, s.cfg.PublicURL+"/settings", http.StatusFound)
}

// handleSettings renders the catalogue, sending the user through the provider
// first when they are not signed in.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	// With nothing to enrol there is nothing to protect, so an anonymous visitor
	// is not sent to the provider just to be told so.
	if !s.reg.Load().HasPerUserTargets() {
		renderSettings(w, settingsView{})
		return
	}
	identity := s.identityFrom(r)
	if identity.Subject == "" {
		s.startLogin(w, r, flowKindSettings, s.settingsRedirectURI())
		return
	}

	enrolled, err := s.store.EnrolledTargets(r.Context(), identity.Subject)
	if err != nil {
		slog.Error("settings: could not read enrolments", "err", err)
		renderError(w, http.StatusInternalServerError, "Something went wrong", "Your saved credentials could not be read. Try again in a moment.")
		return
	}

	view := settingsView{Subject: identity.Label(), Notice: r.URL.Query().Get("notice")}
	for _, e := range s.reg.Load().entries {
		t := e.Target
		if t.Mode != CredPerUser {
			continue
		}
		row := targetRow{Name: t.Name, Display: t.DisplayName, Host: upstreamHost(t), Fields: t.UserFields, Stamp: t.Stamp()}
		if at, ok := enrolled[StampedName{t.Name, row.Stamp}]; ok {
			row.Enrolled = true
			row.UpdatedAt = at.UTC().Format("2006-01-02 15:04 MST")
		}
		view.Targets = append(view.Targets, row)
	}
	sort.Slice(view.Targets, func(i, j int) bool { return view.Targets[i].Display < view.Targets[j].Display })

	renderSettings(w, view)
}

// startLogin sends the browser to the provider. The settings page and the admin
// page both use it, each with its own kind and callback address.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, kind, redirectURI string) {
	meta, err := s.upstream.Meta(r.Context())
	if err != nil {
		slog.Error(kind+": provider discovery failed", "err", err)
		renderError(w, http.StatusBadGateway, "Sign-in unavailable", "The identity provider could not be reached. Try again in a moment.")
		return
	}

	flowID := newSecret()
	verifier := newSecret()
	if err := s.store.CreateSettingsFlow(r.Context(), flowID, verifier, s.browserSecret(w, r), kind); err != nil {
		slog.Error(kind+": could not start a login", "err", err)
		renderError(w, http.StatusInternalServerError, "Something went wrong", "The sign-in could not be started. Try again in a moment.")
		return
	}

	dest, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		renderError(w, http.StatusBadGateway, "Sign-in unavailable", "The identity provider's sign-in address is not usable. Contact the administrator of this proxy.")
		return
	}
	q := dest.Query()
	q.Set("client_id", s.cfg.UpstreamClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", s.cfg.UpstreamScopes)
	q.Set("state", flowID)
	q.Set("code_challenge", s256(verifier))
	q.Set("code_challenge_method", "S256")
	dest.RawQuery = q.Encode()

	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// finishLogin redeems the callback of a login started by startLogin and says who
// signed in. On any failure it has already answered through fail and returns
// false.
func (s *Server) finishLogin(r *http.Request, kind, redirectURI string, fail func(status int, heading, message string)) (UserIdentity, bool) {
	q := r.URL.Query()

	verifier, err := s.store.TakeSettingsFlow(r.Context(), q.Get("state"), s.readBrowserSecret(r), kind)
	if err != nil {
		fail(http.StatusBadRequest, "Sign-in expired", "This sign-in has expired or was already used. Open the "+kind+" page again to sign in.")
		return UserIdentity{}, false
	}
	if e := q.Get("error"); e != "" {
		fail(http.StatusForbidden, "Sign-in refused", "The identity provider refused the sign-in: "+e)
		return UserIdentity{}, false
	}

	tok, err := s.upstream.ExchangeWithRedirect(r.Context(), q.Get("code"), verifier, redirectURI)
	if err != nil {
		slog.Error(kind+": upstream exchange failed", "err", err)
		fail(http.StatusBadGateway, "Sign-in failed", "The identity provider rejected the sign-in. Try again.")
		return UserIdentity{}, false
	}

	// Without a stable subject there is nothing to key a credential on.
	identity, err := s.upstream.Identity(r.Context(), tok.AccessToken)
	if err != nil {
		slog.Error(kind+": could not resolve the user", "err", err)
		msg := "The identity provider would not say who you are."
		if kind == flowKindSettings {
			msg = "The identity provider would not say who you are, so credentials cannot be stored."
		}
		fail(http.StatusBadGateway, "Sign-in failed", msg)
		return UserIdentity{}, false
	}
	return identity, true
}

func (s *Server) handleSettingsCallback(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.finishLogin(r, flowKindSettings, s.settingsRedirectURI(), func(status int, heading, message string) {
		renderSettingsError(w, status, heading, message)
	})
	if !ok {
		return
	}

	if err := s.setIdentity(w, identity); err != nil {
		slog.Error("settings: could not set the session cookie", "err", err)
		renderSettingsError(w, http.StatusInternalServerError, "Something went wrong", "Your session could not be started. Try again.")
		return
	}
	slog.Info("settings: signed in", "subject", identity.Label())
	http.Redirect(w, r, s.cfg.PublicURL+"/settings", http.StatusFound)
}

// handleSettingsSave stores or clears one target's credential for the signed-in
// subject.
func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		slog.Warn("settings: cross-origin submission refused", "origin", r.Header.Get("Origin"))
		renderSettingsError(w, http.StatusForbidden, "Request blocked", "This request did not come from the settings page.")
		return
	}
	identity := s.identityFrom(r)
	if identity.Subject == "" {
		http.Redirect(w, r, s.cfg.PublicURL+"/settings", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderSettingsError(w, http.StatusBadRequest, "Could not read the form", "The form submission was malformed. Go back and try again.")
		return
	}

	// The target comes from the form, so it is matched against configuration
	// rather than trusted. Only a per_user target can be written.
	name := r.PostForm.Get("target")
	var target Target
	for _, e := range s.reg.Load().entries {
		if e.Target.Name == name && e.Target.Mode == CredPerUser {
			target = e.Target
		}
	}
	if target.Name == "" {
		renderSettingsError(w, http.StatusBadRequest, "Unknown server", "That server is not one this proxy keeps personal credentials for.")
		return
	}

	// The form carries the stamp of the definition it was rendered under. If the
	// server's settings have changed since, what the person typed was meant for a
	// different destination and is not stored.
	stamp := target.Stamp()
	if r.PostForm.Get("stamp") != stamp {
		renderSettingsError(w, http.StatusConflict, "Settings changed",
			"This server's settings changed after the page was loaded. Reload the page and try again.")
		return
	}

	if r.PostForm.Get("action") == "clear" {
		if err := s.store.DeleteUserCredential(r.Context(), identity.Subject, target.Name, stamp); err != nil {
			slog.Error("settings: could not clear the credential", "err", err, "target", target.Name)
			renderSettingsError(w, http.StatusInternalServerError, "Something went wrong", "The credential could not be removed. Try again.")
			return
		}
		slog.Info("settings: credential cleared", "subject", identity.Label(), "target", target.Name)
		http.Redirect(w, r, s.cfg.PublicURL+"/settings?notice=cleared", http.StatusFound)
		return
	}

	headers := map[string]string{}
	for _, f := range target.UserFields {
		v := strings.TrimSpace(r.PostForm.Get("field_" + f.Header))
		if v == "" {
			renderSettingsError(w, http.StatusBadRequest, "A field was empty", "Every field is required, and "+f.Label+" was empty.")
			return
		}
		if len(v) > maxCredentialValue {
			renderSettingsError(w, http.StatusBadRequest, "A value is too long", f.Label+" is too long.")
			return
		}
		// Rejected here rather than on the way out. A control character survives
		// TrimSpace and is refused by the transport at request time, which would
		// give this user a 502 on every subsequent call with nothing on screen to
		// explain it, and a stored row that can only ever fail.
		if !httpguts.ValidHeaderFieldValue(f.Prefix + v) {
			renderSettingsError(w, http.StatusBadRequest, "A value is not valid", f.Label+" contains characters that are not allowed in an HTTP header. Check that you pasted only the token.")
			return
		}
		headers[f.Header] = f.Prefix + v
	}

	raw, err := json.Marshal(headers)
	if err != nil {
		renderSettingsError(w, http.StatusInternalServerError, "Something went wrong", "The credential could not be saved. Try again.")
		return
	}
	sealed, err := s.sealer.seal(boundPurpose(purposeUserCredential, stamp), raw)
	if err != nil {
		slog.Error("settings: could not seal the credential", "err", err)
		renderSettingsError(w, http.StatusInternalServerError, "Something went wrong", "The credential could not be saved. Try again.")
		return
	}
	err = s.store.PutUserCredential(r.Context(), identity.Subject, target.Name, stamp, sealed)
	if errors.Is(err, ErrStaleTarget) {
		// The definition changed between the page loading and this write, on a
		// replica that had not yet seen it. Nothing was stored.
		renderSettingsError(w, http.StatusConflict, "Settings changed",
			"This server's settings changed after the page was loaded. Reload the page and try again.")
		return
	}
	if err != nil {
		slog.Error("settings: could not store the credential", "err", err, "target", target.Name)
		renderSettingsError(w, http.StatusInternalServerError, "Something went wrong", "The credential could not be saved. Try again.")
		return
	}

	// The values themselves are never logged, only that something was stored.
	slog.Info("settings: credential stored", "subject", identity.Label(), "target", target.Name,
		"headers", len(headers))
	http.Redirect(w, r, s.cfg.PublicURL+"/settings?notice=saved", http.StatusFound)
}

// userHeadersFor unseals the caller's credential for a target. It returns
// errBehind, with nothing unsealed, when the database holds a different
// definition of the target than the entry this replica is serving.
func (s *Server) userHeadersFor(r *http.Request, sessionID string, e *entry) (map[string]string, error) {
	sealed, current, err := s.store.UserCredentialForSession(r.Context(), sessionID, e.Target.Name)
	if err != nil {
		return nil, err
	}
	if s.reg.enabled() && e.behind(current) {
		return nil, errBehind
	}
	raw, err := s.sealer.open(boundPurpose(purposeUserCredential, e.Stamp), sealed)
	if err != nil {
		return nil, err
	}
	var headers map[string]string
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, err
	}
	if len(headers) == 0 {
		return nil, errors.New("stored credential is empty")
	}
	return headers, nil
}

// ---------- rendering ----------

type targetRow struct {
	// Name is the identifier posted back and matched against configuration.
	// Display is only ever shown.
	Name    string
	Display string
	Host    string
	// Stamp is posted back so a save can tell the definition it was rendered
	// under from the one being served when it arrives.
	Stamp     string
	Fields    []UserHeaderField
	Enrolled  bool
	UpdatedAt string
}

type settingsView struct {
	Subject string
	Notice  string
	Targets []targetRow
}

var settingsTemplate = newPage("settings")

func renderSettings(w http.ResponseWriter, v settingsView) {
	// The form posts only to this origin, unlike consent, which has to redirect
	// on to the provider.
	writePage(w, http.StatusOK, settingsTemplate, "'self'", v)
}
