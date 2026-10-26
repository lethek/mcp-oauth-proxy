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
var consentTemplate = newPage(`{{define "title"}}Allow {{.ClientName}}?{{end}}
{{define "content"}}
<main class="card">
  <p class="eyebrow">Access request</p>
  <h1>Allow {{.ClientName}} to access {{.TargetName}}?</h1>
  <p class="lede">If you approve, it can do anything your account can do there.</p>

  <div class="facts">
    <dl>
      <div>
        <dt>Application</dt>
        <dd>{{.ClientName}}</dd>
      </div>
      <div>
        <dt>Sends you back to</dt>
        <dd class="mono">{{.RedirectURI}}</dd>
      </div>
    </dl>
    <details>
      <summary>Technical details</summary>
      <p class="mono">Client ID: {{.ClientID}}</p>
    </details>
  </div>

  <div class="callout" role="note">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/></svg>
    <p>Anyone can register an application here, and its name is whatever it chose to
    call itself. Approve only if you just started this yourself and the address
    above is the one you expect.</p>
  </div>

  <form method="POST" action="{{.ConsentPath}}">
    <input type="hidden" name="flow_id" value="{{.FlowID}}">
    <div class="actions">
      <button type="submit" name="decision" value="deny" class="btn">Cancel</button>
      <button type="submit" name="decision" value="approve" class="btn btn-primary">Allow access</button>
    </div>
  </form>
</main>
<p class="fine">After you allow access you will be asked to sign in with your identity provider.</p>
{{end}}`)

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
