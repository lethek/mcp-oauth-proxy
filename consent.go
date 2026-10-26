package main

import (
	"net/http"
	"net/url"
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
//
// The decision is one question with two answers. What the person must check (who
// is asking, and where the result is sent) is shown; the client id, which only
// matters when reporting a problem, is folded away. The warning sits next to the
// buttons because that is where the decision is made.
var consentTemplate = newPage("consent")

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
	// form-action has to name the provider as well as this origin. The browser
	// applies it to every hop of the redirect chain a submission triggers, so
	// listing only 'self' blocks the redirect to the provider that approval
	// depends on, leaving the page apparently doing nothing. The client's
	// redirect_uri is the last hop of both Cancel and Approve, so it is named too.
	formAction := append([]string{"'self'"}, v.ProviderOrigins...)
	if src := redirectSource(v.RedirectURI); src != "" {
		formAction = append(formAction, src)
	}
	writePage(w, http.StatusOK, consentTemplate, strings.Join(formAction, " "), v)
}

// redirectSource turns a registered redirect URI into a CSP source expression:
// its origin for http and https, or a scheme-source such as "com.example.app:"
// for a native app's private-use scheme, which has no origin.
func redirectSource(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return ""
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		return canonicalOrigin(u)
	}
	return u.Scheme + ":"
}
