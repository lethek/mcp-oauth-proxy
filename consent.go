package main

import (
	"html/template"
	"net/http"
	"strings"
)

// consentTemplate renders the interstitial that closes the confused-deputy
// hole. Everything variable in it comes from an anonymous registration, so it
// is rendered with html/template and never with string concatenation.
//
// The page carries the flow id in a hidden field. That id is generated server
// side and appears nowhere except in this response, so it doubles as the CSRF
// token: whoever crafted the /authorize link cannot forge the POST that follows
// because they never see the id.
var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>Authorize {{.ClientName}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         line-height: 1.5; margin: 0; padding: 2rem 1rem;
         display: flex; justify-content: center; }
  main { max-width: 32rem; width: 100%; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  dl { margin: 1.5rem 0; padding: 1rem; border: 1px solid currentColor;
       border-radius: 6px; opacity: 0.95; }
  dt { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
       opacity: 0.7; margin-top: 0.75rem; }
  dt:first-child { margin-top: 0; }
  dd { margin: 0.15rem 0 0; word-break: break-all; font-family: ui-monospace, monospace; }
  .warn { font-size: 0.9rem; opacity: 0.8; }
  .actions { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
  button { font: inherit; padding: 0.6rem 1.2rem; border-radius: 6px;
           border: 1px solid currentColor; cursor: pointer; }
  button.primary { font-weight: 600; }
</style>
</head>
<body>
<main>
  <h1>Authorize {{.ClientName}}</h1>

  <p>An application is asking to act as you on {{.TargetName}}. If you approve,
  it can do anything your account can do there.</p>

  <dl>
    <dt>Application name</dt>
    <dd>{{.ClientName}}</dd>
    <dt>Will act on your behalf at</dt>
    <dd>{{.TargetName}}</dd>
    <dt>Client ID</dt>
    <dd>{{.ClientID}}</dd>
    <dt>Will receive the authorization at</dt>
    <dd>{{.RedirectURI}}</dd>
  </dl>

  <p class="warn">Anyone can register an application here, and the name above is
  whatever it chose to call itself. Approve this only if you started it
  yourself, and only if the address above belongs to the application you
  expected.</p>

  <form method="POST" action="{{.ConsentPath}}">
    <input type="hidden" name="flow_id" value="{{.FlowID}}">
    <div class="actions">
      <button type="submit" name="decision" value="approve" class="primary">Approve</button>
      <button type="submit" name="decision" value="deny">Cancel</button>
    </div>
  </form>
</main>
</body>
</html>
`))

type consentView struct {
	ClientName string
	ClientID   string

	// TargetName is which MCP server this authorization is for. With several
	// targets behind one proxy, approving a client no longer implies which
	// credential it will end up spending, so the question has to name it.
	TargetName string

	RedirectURI string
	FlowID      string
	ConsentPath string

	// ProviderOrigins are the origins the browser will be sent to after this
	// form is submitted. They have to appear in form-action or the browser
	// refuses the redirect.
	ProviderOrigins []string
}

func renderConsent(w http.ResponseWriter, v consentView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// same-origin, not no-referrer. Under a no-referrer policy the Fetch spec has
	// the browser serialise the Origin header of this page's own form submission
	// as "null", so the page would guarantee that every submission it produces
	// fails its own origin check. same-origin still withholds the referrer from
	// anywhere else, which is the only place it could leak.
	w.Header().Set("Referrer-Policy", "same-origin")
	// The page contains a one-time credential and must never be framed by the
	// site that sent the user here.
	w.Header().Set("X-Frame-Options", "DENY")
	// form-action has to name the provider as well as this origin. The browser
	// applies it to every hop of the redirect chain a submission triggers, so
	// listing only 'self' blocks the redirect to the provider that approval
	// depends on, leaving the page apparently doing nothing.
	formAction := append([]string{"'self'"}, v.ProviderOrigins...)
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action "+strings.Join(formAction, " ")+
			"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	_ = consentTemplate.Execute(w, v)
}
