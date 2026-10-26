package main

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
)

// Every page a person sees shares one shell and one stylesheet, so the consent
// screen, the credentials page and the error page read as the same product. The
// markup lives in templates/, one file per page plus base.html for the shell,
// and is compiled into the binary.
//
// The design is deliberately plain: a single centred card on a quiet
// background, one accent colour reserved for the action that moves the person
// forward, and amber and red used only for caution and for destructive actions.
// It follows the system light or dark setting. There is no script and no
// external font or stylesheet, because the Content-Security-Policy on these
// pages allows neither. The stylesheet is therefore inlined into each page.
//
//go:embed templates
var templateFS embed.FS

var pageStyles = func() template.CSS {
	css, err := templateFS.ReadFile("templates/styles.css")
	if err != nil {
		panic(err)
	}
	return template.CSS(css)
}()

// newPage builds a page from the shared shell and templates/<name>.html, which
// must define the "title" and "content" templates.
func newPage(name string) *template.Template {
	return template.Must(template.New("page").
		Funcs(template.FuncMap{"styles": func() template.CSS { return pageStyles }}).
		ParseFS(templateFS, "templates/base.html", "templates/"+name+".html"))
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

var errorTemplate = newPage("error")

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
