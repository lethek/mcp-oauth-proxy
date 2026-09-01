package main

import (
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The enrolment page needs its own notion of "this browser is this person",
// which the OAuth endpoints do not have: the consent screen is bound to one
// in-flight authorization and means nothing outside it. So /settings runs its
// own authorization-code round trip and keeps the result in a sealed cookie.
const (
	settingsCookie  = "mcp_settings"
	settingsSession = 12 * time.Hour
)

// settingsIdentity is what the cookie carries. It is sealed rather than signed,
// using the same key as the stored credentials, so the subject is not readable
// by the browser holding it.
type settingsIdentity struct {
	Subject string `json:"sub"`
	Expires int64  `json:"exp"`
}

func (s *Server) settingsRedirectURI() string { return s.cfg.PublicURL + "/settings/callback" }

// identityFrom returns the signed-in subject, or "" when there is no usable
// session. Any failure to open or decode the cookie is treated as absent: a
// tampered or stale cookie should send the user back through the provider, not
// produce an error page.
func (s *Server) identityFrom(r *http.Request) string {
	c, err := r.Cookie(settingsCookie)
	if err != nil {
		return ""
	}
	raw, err := s.sealer.openString(c.Value)
	if err != nil {
		return ""
	}
	var id settingsIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return ""
	}
	if id.Subject == "" || time.Now().Unix() > id.Expires {
		return ""
	}
	return id.Subject
}

func (s *Server) setIdentity(w http.ResponseWriter, subject string) error {
	raw, err := json.Marshal(settingsIdentity{
		Subject: subject,
		Expires: time.Now().Add(settingsSession).Unix(),
	})
	if err != nil {
		return err
	}
	sealed, err := s.sealer.sealString(raw)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     settingsCookie,
		Value:    sealed,
		Path:     "/settings",
		HttpOnly: true,
		Secure:   s.cfg.PublicScheme == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(settingsSession.Seconds()),
	})
	return nil
}

// handleSettings renders the catalogue, sending the user through the provider
// first when they are not signed in.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	subject := s.identityFrom(r)
	if subject == "" {
		s.startSettingsLogin(w, r)
		return
	}

	enrolled, err := s.store.EnrolledTargets(r.Context(), subject)
	if err != nil {
		slog.Error("settings: could not read enrolments", "err", err)
		http.Error(w, "Could not read your saved credentials.", http.StatusInternalServerError)
		return
	}

	view := settingsView{Subject: subject, Notice: r.URL.Query().Get("notice")}
	for _, t := range s.cfg.Targets {
		if t.Mode != CredPerUser {
			continue
		}
		row := targetRow{Name: t.Name, Fields: t.UserFields}
		if at, ok := enrolled[t.Name]; ok {
			row.Enrolled = true
			row.UpdatedAt = at.UTC().Format("2006-01-02 15:04 MST")
		}
		view.Targets = append(view.Targets, row)
	}
	sort.Slice(view.Targets, func(i, j int) bool { return view.Targets[i].Name < view.Targets[j].Name })

	renderSettings(w, view)
}

func (s *Server) startSettingsLogin(w http.ResponseWriter, r *http.Request) {
	meta, err := s.upstream.Meta(r.Context())
	if err != nil {
		slog.Error("settings: provider discovery failed", "err", err)
		http.Error(w, "The identity provider is not reachable.", http.StatusBadGateway)
		return
	}

	flowID := newSecret()
	verifier := newSecret()
	if err := s.store.CreateSettingsFlow(r.Context(), flowID, verifier, s.browserSecret(w, r)); err != nil {
		slog.Error("settings: could not start a login", "err", err)
		http.Error(w, "Could not start the sign-in.", http.StatusInternalServerError)
		return
	}

	dest, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, "The identity provider's authorization endpoint is unusable.", http.StatusBadGateway)
		return
	}
	q := dest.Query()
	q.Set("client_id", s.cfg.UpstreamClientID)
	q.Set("redirect_uri", s.settingsRedirectURI())
	q.Set("response_type", "code")
	q.Set("scope", s.cfg.UpstreamScopes)
	q.Set("state", flowID)
	q.Set("code_challenge", s256(verifier))
	q.Set("code_challenge_method", "S256")
	dest.RawQuery = q.Encode()

	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (s *Server) handleSettingsCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	verifier, err := s.store.TakeSettingsFlow(r.Context(), q.Get("state"), readBrowserSecret(r))
	if err != nil {
		http.Error(w, "This sign-in has expired or was already used. Open the settings page again.", http.StatusBadRequest)
		return
	}
	if e := q.Get("error"); e != "" {
		http.Error(w, "The identity provider refused the sign-in: "+e, http.StatusForbidden)
		return
	}

	tok, err := s.upstream.ExchangeWithRedirect(r.Context(), q.Get("code"), verifier, s.settingsRedirectURI())
	if err != nil {
		slog.Error("settings: upstream exchange failed", "err", err)
		http.Error(w, "The identity provider rejected the sign-in.", http.StatusBadGateway)
		return
	}

	// Without a subject there is nothing to key a credential on, so this cannot
	// fall through the way the MCP login does.
	subject, err := s.upstream.Subject(r.Context(), tok.AccessToken)
	if err != nil || subject == "" {
		slog.Error("settings: could not resolve the user", "err", err)
		http.Error(w, "The identity provider would not say who you are, so credentials cannot be stored.", http.StatusBadGateway)
		return
	}

	if err := s.setIdentity(w, subject); err != nil {
		slog.Error("settings: could not set the session cookie", "err", err)
		http.Error(w, "Could not start your session.", http.StatusInternalServerError)
		return
	}
	slog.Info("settings: signed in", "subject", subject)
	http.Redirect(w, r, s.cfg.PublicURL+"/settings", http.StatusFound)
}

// handleSettingsSave stores or clears one target's credential for the signed-in
// subject.
func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		slog.Warn("settings: cross-origin submission refused", "origin", r.Header.Get("Origin"))
		http.Error(w, "This request did not come from the settings page.", http.StatusForbidden)
		return
	}
	subject := s.identityFrom(r)
	if subject == "" {
		http.Redirect(w, r, s.cfg.PublicURL+"/settings", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Malformed form submission.", http.StatusBadRequest)
		return
	}

	// The target comes from the form, so it is matched against configuration
	// rather than trusted. Only a per_user target can be written.
	name := r.PostForm.Get("target")
	var target Target
	for _, t := range s.cfg.Targets {
		if t.Name == name && t.Mode == CredPerUser {
			target = t
		}
	}
	if target.Name == "" {
		http.Error(w, "Unknown target.", http.StatusBadRequest)
		return
	}

	if r.PostForm.Get("action") == "clear" {
		if err := s.store.DeleteUserCredential(r.Context(), subject, target.Name); err != nil {
			slog.Error("settings: could not clear the credential", "err", err, "target", target.Name)
			http.Error(w, "Could not clear the credential.", http.StatusInternalServerError)
			return
		}
		slog.Info("settings: credential cleared", "subject", subject, "target", target.Name)
		http.Redirect(w, r, s.cfg.PublicURL+"/settings?notice=cleared", http.StatusFound)
		return
	}

	headers := map[string]string{}
	for _, f := range target.UserFields {
		v := strings.TrimSpace(r.PostForm.Get("field_" + f.Header))
		if v == "" {
			http.Error(w, "Every field is required: "+f.Label+" was empty.", http.StatusBadRequest)
			return
		}
		headers[f.Header] = f.Prefix + v
	}

	raw, err := json.Marshal(headers)
	if err != nil {
		http.Error(w, "Could not store the credential.", http.StatusInternalServerError)
		return
	}
	sealed, err := s.sealer.seal(raw)
	if err != nil {
		slog.Error("settings: could not seal the credential", "err", err)
		http.Error(w, "Could not store the credential.", http.StatusInternalServerError)
		return
	}
	if err := s.store.PutUserCredential(r.Context(), subject, target.Name, sealed); err != nil {
		slog.Error("settings: could not store the credential", "err", err, "target", target.Name)
		http.Error(w, "Could not store the credential.", http.StatusInternalServerError)
		return
	}

	// The values themselves are never logged, only that something was stored.
	slog.Info("settings: credential stored", "subject", subject, "target", target.Name,
		"headers", len(headers))
	http.Redirect(w, r, s.cfg.PublicURL+"/settings?notice=saved", http.StatusFound)
}

// userHeadersFor unseals the caller's credential for a target.
func (s *Server) userHeadersFor(r *http.Request, sessionID, target string) (map[string]string, error) {
	sealed, err := s.store.UserCredentialForSession(r.Context(), sessionID, target)
	if err != nil {
		return nil, err
	}
	raw, err := s.sealer.open(sealed)
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
	Name      string
	Fields    []UserHeaderField
	Enrolled  bool
	UpdatedAt string
}

type settingsView struct {
	Subject string
	Notice  string
	Targets []targetRow
}

var settingsTemplate = template.Must(template.New("settings").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP credentials</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
 h1{font-size:1.4rem} h2{font-size:1.1rem;margin-bottom:.25rem}
 .card{border:1px solid #ccc;border-radius:.5rem;padding:1rem;margin:1rem 0}
 .state{color:#555;font-size:.9rem;margin-top:0}
 label{display:block;margin:.75rem 0 .25rem;font-size:.9rem}
 input[type=text]{width:100%;padding:.5rem;box-sizing:border-box}
 button{padding:.5rem 1rem;margin-top:.75rem}
 .notice{background:#eef;border:1px solid #99c;padding:.5rem 1rem;border-radius:.5rem}
 .who{color:#555;font-size:.9rem}
</style></head><body>
<h1>MCP credentials</h1>
<p class="who">Signed in as {{.Subject}}</p>
{{if .Notice}}<p class="notice">{{if eq .Notice "saved"}}Credential saved.{{else}}Credential cleared.{{end}}</p>{{end}}
{{if not .Targets}}<p>No target on this proxy asks for a credential of your own.</p>{{end}}
{{range .Targets}}
<div class="card">
  <h2>{{.Name}}</h2>
  {{if .Enrolled}}<p class="state">Configured, last updated {{.UpdatedAt}}.</p>
  {{else}}<p class="state">Not configured. This target will refuse your requests until you set one.</p>{{end}}
  <form method="post" action="/settings">
    <input type="hidden" name="target" value="{{.Name}}">
    {{range .Fields}}
    <label for="{{$.Subject}}-{{.Header}}">{{.Label}}</label>
    <input type="text" id="{{$.Subject}}-{{.Header}}" name="field_{{.Header}}" autocomplete="off" spellcheck="false" required>
    {{end}}
    <button type="submit" name="action" value="save">{{if .Enrolled}}Replace{{else}}Save{{end}}</button>
    {{if .Enrolled}}<button type="submit" name="action" value="clear">Clear</button>{{end}}
  </form>
</div>
{{end}}
</body></html>`))

func renderSettings(w http.ResponseWriter, v settingsView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	// The form posts only to this origin, unlike consent, which has to redirect
	// on to the provider.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	if err := settingsTemplate.Execute(w, v); err != nil {
		slog.Error("settings: render failed", "err", err)
	}
}
