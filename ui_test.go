package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func twoTargetSettings() settingsView {
	fields := []UserHeaderField{{Header: "Authorization", Label: "Token", Prefix: "Bearer "}}
	return settingsView{
		Subject: "someone@example.com",
		Targets: []targetRow{
			{Name: "alpha", Display: "Alpha", Fields: fields, Enrolled: true, UpdatedAt: "2026-01-02 03:04 UTC"},
			{Name: "beta", Display: "Beta", Fields: fields},
		},
	}
}

// Every field is required, so a Remove button that validates the form can never
// be used: the browser stops the submission until a new value has been typed.
func TestRemoveButtonSkipsFieldValidation(t *testing.T) {
	rec := httptest.NewRecorder()
	renderSettings(rec, twoTargetSettings())

	body := rec.Body.String()
	i := strings.Index(body, `value="clear"`)
	if i < 0 {
		t.Fatal("no Remove button on the page for a configured target")
	}
	end := strings.Index(body[i:], ">")
	if !strings.Contains(body[i:i+end], "formnovalidate") {
		t.Error("the Remove button validates the form, so it is blocked by the empty required fields")
	}
}

// Two targets that ask for the same header would otherwise share a field id,
// leaving the second label pointing at the first input.
func TestSettingsFieldIDsAreUniquePerTarget(t *testing.T) {
	rec := httptest.NewRecorder()
	renderSettings(rec, twoTargetSettings())

	body := rec.Body.String()
	for _, id := range []string{`id="cred-alpha-Authorization"`, `id="cred-beta-Authorization"`} {
		if strings.Count(body, id) != 1 {
			t.Errorf("want exactly one %s", id)
		}
	}
}

func TestErrorPageKeepsStatusAndEscapesTheMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	renderError(rec, http.StatusBadRequest, "Heading", `<script>alert(1)</script>`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want HTML", ct)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("the error page can be framed")
	}
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("the message was rendered unescaped")
	}
}
