package main

import (
	"html/template"
	"log/slog"
	"net/http"
)

// Every page a person sees shares one shell and one stylesheet, so the consent
// screen, the credentials page and the error page read as the same product.
//
// The design is deliberately plain: a single centred card on a quiet
// background, one accent colour reserved for the action that moves the person
// forward, and amber and red used only for caution and for destructive actions.
// It follows the system light or dark setting. There is no script and no
// external font, because the Content-Security-Policy on these pages allows
// neither.
const pageStyles = `
:root {
  color-scheme: light dark;
  --bg: #f4f5f7;
  --surface: #ffffff;
  --text: #151a23;
  --muted: #586174;
  --border: #dfe3ea;
  --accent: #3451d1;
  --accent-hover: #2a43b3;
  --on-accent: #ffffff;
  --ok-bg: #e7f5ec;
  --ok-text: #11663a;
  --warn-bg: #fff6dc;
  --warn-border: #ecd48a;
  --warn-text: #5f4500;
  --danger: #b42318;
  --danger-bg: #fdecea;
  --focus: #3451d1;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 8px 24px rgba(16, 24, 40, .06);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1016;
    --surface: #171b23;
    --text: #e9ecf2;
    --muted: #9ba5b7;
    --border: #2a303b;
    --accent: #8ba2ff;
    --accent-hover: #a5b6ff;
    --on-accent: #0b1020;
    --ok-bg: #12301f;
    --ok-text: #7fdca4;
    --warn-bg: #2e2508;
    --warn-border: #5c4a12;
    --warn-text: #f1d77c;
    --danger: #ff8a80;
    --danger-bg: #3a1613;
    --focus: #8ba2ff;
    --shadow: 0 1px 2px rgba(0, 0, 0, .4), 0 8px 24px rgba(0, 0, 0, .35);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-text-size-adjust: 100%;
}
.shell { max-width: 34rem; margin: 0 auto; padding: 2rem 1rem 3rem; }
.brand {
  display: flex; align-items: center; gap: .5rem;
  margin: 0 0 1.25rem .25rem;
  color: var(--muted); font-size: .875rem; font-weight: 600; letter-spacing: .01em;
}
.brand svg { width: 1.25rem; height: 1.25rem; color: var(--accent); flex: none; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  box-shadow: var(--shadow);
  padding: 1.5rem;
  margin: 0 0 1rem;
}
h1 { font-size: 1.5rem; line-height: 1.25; margin: 0 0 .5rem; letter-spacing: -.01em; }
h2 { font-size: 1.1rem; line-height: 1.3; margin: 0; }
p { margin: 0 0 .75rem; }
.lede { color: var(--muted); margin-bottom: 0; }
.muted { color: var(--muted); }
.fine { color: var(--muted); font-size: .8125rem; margin: .5rem .25rem 1rem; }
.eyebrow {
  margin: 0 0 .5rem; color: var(--accent);
  font-size: .75rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase;
}
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .875rem; overflow-wrap: anywhere; }

.facts { margin: 1.25rem 0 0; border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.facts dl { margin: 0; }
.facts dl > div { padding: .75rem 1rem; }
.facts dl > div + div, .facts details { border-top: 1px solid var(--border); }
.facts dt { color: var(--muted); font-size: .75rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
.facts dd { margin: .125rem 0 0; overflow-wrap: anywhere; }
.facts details { padding: .625rem 1rem; }
.facts summary { cursor: pointer; color: var(--muted); font-size: .875rem; }
.facts summary:hover { color: var(--text); }
.facts details p { margin: .5rem 0 0; }

.callout {
  display: flex; gap: .75rem; align-items: flex-start;
  margin: 1rem 0 0; padding: .875rem 1rem;
  background: var(--warn-bg); border: 1px solid var(--warn-border); border-radius: 10px;
  color: var(--warn-text); font-size: .9375rem;
}
.callout svg { width: 1.25rem; height: 1.25rem; flex: none; margin-top: .125rem; }
.callout p { margin: 0; }

.banner {
  margin: 0 0 1rem; padding: .75rem 1rem; border-radius: 10px;
  background: var(--ok-bg); color: var(--ok-text); font-weight: 600;
}

.actions { display: flex; flex-direction: column-reverse; gap: .625rem; margin-top: 1.5rem; }
.row { display: flex; flex-wrap: wrap; gap: .625rem; margin-top: 1rem; }
@media (min-width: 30rem) {
  .actions { flex-direction: row; justify-content: flex-end; }
}
.btn {
  appearance: none; font: inherit; font-weight: 600; line-height: 1.2;
  min-height: 2.75rem; padding: .625rem 1.25rem;
  border-radius: 10px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); cursor: pointer;
  text-decoration: none; display: inline-flex; align-items: center; justify-content: center;
}
.btn:hover { border-color: var(--muted); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
.btn-danger { color: var(--danger); }
.btn-danger:hover { background: var(--danger-bg); border-color: var(--danger); }
.btn-sm { min-height: 2.25rem; padding: .375rem .875rem; font-size: .875rem; }
a { color: var(--accent); }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }

.account {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .75rem;
  padding: .625rem .625rem .625rem 1rem; margin: 1.25rem 0 0;
  background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
}
.account form { margin: 0; }
.page-head { margin: 0 .25rem; }

.card-head { display: flex; align-items: center; justify-content: space-between; gap: .75rem; margin-bottom: .5rem; }
.pill {
  flex: none; padding: .125rem .625rem; border-radius: 999px;
  border: 1px solid var(--border); color: var(--muted);
  font-size: .75rem; font-weight: 700; letter-spacing: .02em;
}
.pill-ok { background: var(--ok-bg); border-color: transparent; color: var(--ok-text); }
.field { margin-top: 1rem; }
label { display: block; margin: 0 0 .375rem; font-size: .9375rem; font-weight: 600; }
.input {
  width: 100%; min-height: 2.75rem; padding: .5rem .75rem;
  font: inherit; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9375rem;
  color: var(--text); background: var(--bg);
  border: 1px solid var(--border); border-radius: 10px;
}
.input:hover { border-color: var(--muted); }
.hint { margin: .375rem 0 0; color: var(--muted); font-size: .8125rem; }
.empty { text-align: center; color: var(--muted); }
`

const lockIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/><path d="M9.5 12l2 2 3.5-4"/></svg>`

var pageBase = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="same-origin">
<title>{{template "title" .}} | MCP OAuth Proxy</title>
<style>` + pageStyles + `</style>
</head>
<body>
<div class="shell">
  <div class="brand">` + lockIcon + `<span>MCP OAuth Proxy</span></div>
  {{template "content" .}}
</div>
</body>
</html>
`))

// newPage builds a page from the shared shell. content must define the "title"
// and "content" templates.
func newPage(content string) *template.Template {
	return template.Must(template.Must(pageBase.Clone()).Parse(content))
}

// writePage sends a page with the headers every one of them needs.
//
// same-origin, not no-referrer. Under a no-referrer policy the Fetch spec has
// the browser serialise the Origin header of the page's own form submission as
// "null", so the page would guarantee that every submission it produces fails
// its own origin check. same-origin still withholds the referrer from anywhere
// else, which is the only place it could leak.
//
// The pages can hold a one-time credential or a form that acts for the user, so
// they must never be framed by the site that sent the user here.
//
// formAction is the CSP form-action source list. The browser applies it to every
// hop of the redirect chain a submission triggers, so a page whose form ends up
// at the provider or the client has to name them.
func writePage(w http.ResponseWriter, status int, t *template.Template, formAction string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+
			"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "page", data); err != nil {
		slog.Error("render failed", "err", err)
	}
}

type errorView struct {
	Heading string
	Message string
	// BackHref and BackLabel offer a way forward when there is one on this
	// server. Left empty when the way forward is to start again from the client,
	// which this server cannot link to.
	BackHref  string
	BackLabel string
}

var errorTemplate = newPage(`{{define "title"}}{{.Heading}}{{end}}
{{define "content"}}
<main class="card">
  <h1>{{.Heading}}</h1>
  <p class="lede">{{.Message}}</p>
  {{if .BackHref}}<div class="row"><a class="btn btn-primary" href="{{.BackHref}}">{{.BackLabel}}</a></div>{{end}}
</main>
{{end}}`)

// renderError replaces http.Error for anything a person reads in a browser. The
// status code is unchanged; the body is a page that says what happened and what
// to do next instead of a bare line of text.
func renderError(w http.ResponseWriter, status int, heading, message string) {
	writePage(w, status, errorTemplate, "'self'", errorView{Heading: heading, Message: message})
}

// renderSettingsError is renderError with a way back to the credentials page.
func renderSettingsError(w http.ResponseWriter, status int, heading, message string) {
	writePage(w, status, errorTemplate, "'self'", errorView{
		Heading: heading, Message: message, BackHref: "/settings", BackLabel: "Back to settings",
	})
}
