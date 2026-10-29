package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func baseTarget() Target {
	return Target{
		Name:        "plane",
		DisplayName: "Plane",
		UpstreamMCP: "https://plane.example/mcp",
		Mode:        CredPerUser,
		UserFields: []UserHeaderField{
			{Header: "Authorization", Label: "Token", Prefix: "Bearer "},
			{Header: "x-workspace-slug", Label: "Workspace"},
		},
	}
}

func TestStampIsStableAndTagged(t *testing.T) {
	a, b := baseTarget().Stamp(), baseTarget().Stamp()
	if a != b {
		t.Fatalf("stamp differs between identical definitions: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "config:") {
		t.Errorf("stamp = %q, want a config: prefix", a)
	}
}

func TestStampChangesWithWhereCredentialsGo(t *testing.T) {
	base := baseTarget().Stamp()
	changes := map[string]func(*Target){
		"name":   func(x *Target) { x.Name = "plane2" },
		"url":    func(x *Target) { x.UpstreamMCP = "https://other.example/mcp" },
		"mode":   func(x *Target) { x.Mode = CredProviderToken },
		"header": func(x *Target) { x.UserFields[0].Header = "X-Api-Key" },
		"prefix": func(x *Target) { x.UserFields[0].Prefix = "Token " },
		"order":  func(x *Target) { x.UserFields[0], x.UserFields[1] = x.UserFields[1], x.UserFields[0] },
		"added":  func(x *Target) { x.UserFields = append(x.UserFields, UserHeaderField{Header: "X-Extra"}) },
	}
	for name, mutate := range changes {
		x := baseTarget()
		x.UserFields = append([]UserHeaderField(nil), x.UserFields...)
		mutate(&x)
		if x.Stamp() == base {
			t.Errorf("changing the %s did not change the stamp", name)
		}
	}
}

func TestStampIgnoresWhatDoesNotMoveCredentials(t *testing.T) {
	base := baseTarget().Stamp()
	changes := map[string]func(*Target){
		"label":          func(x *Target) { x.UserFields[0].Label = "Renamed" },
		"display name":   func(x *Target) { x.DisplayName = "Plane Cloud" },
		"allowed groups": func(x *Target) { x.AllowedGroups = []string{"staff"} },
		"static headers": func(x *Target) { x.StaticHeaders = map[string]string{"X-Key": "v"} },
		"resource":       func(x *Target) { x.Resource = "https://proxy.example/plane/mcp" },
	}
	for name, mutate := range changes {
		x := baseTarget()
		x.UserFields = append([]UserHeaderField(nil), x.UserFields...)
		mutate(&x)
		if x.Stamp() != base {
			t.Errorf("changing the %s changed the stamp", name)
		}
	}
}

func TestStampEncodingIsUnambiguous(t *testing.T) {
	a := Target{Name: "a", UpstreamMCP: "bc"}
	b := Target{Name: "ab", UpstreamMCP: "c"}
	if a.Stamp() == b.Stamp() {
		t.Error("different definitions encode to the same stamp")
	}
}

func TestStampDistinguishesInvalidUTF8(t *testing.T) {
	a := Target{Name: "a", UpstreamMCP: "https://x.example/p\xff"}
	b := Target{Name: "a", UpstreamMCP: "https://x.example/p\xfe"}
	if a.Stamp() == b.Stamp() {
		t.Error("URLs differing only in invalid bytes share a stamp")
	}
}

// An admin stamp is the documented formula, written out here by hand so a change
// to Stamp() cannot move both sides at once.
func TestAdminStampFollowsTheSpecFormula(t *testing.T) {
	x := baseTarget()
	x.Source, x.Generation = SourceAdmin, "6f1c2d3e-0000-4000-8000-000000000001"

	want := `1 "plane" "https://plane.example/mcp" "per_user" 2 "Authorization" "Bearer " "x-workspace-slug" "" "6f1c2d3e-0000-4000-8000-000000000001"`
	sum := sha256.Sum256([]byte(want))
	if got, exp := x.Stamp(), "admin:"+hex.EncodeToString(sum[:]); got != exp {
		t.Errorf("stamp = %q, want %q", got, exp)
	}
}

// Every replacement re-rolls the generation, so a definition put back after an
// edit still gets a stamp nothing earlier can match, and a config target ignores
// a generation it was never meant to carry.
func TestAdminStampDependsOnSourceAndGeneration(t *testing.T) {
	config := baseTarget()
	a, b := baseTarget(), baseTarget()
	a.Source, a.Generation = SourceAdmin, "g1"
	b.Source, b.Generation = SourceAdmin, "g2"

	if a.Stamp() == b.Stamp() {
		t.Error("two generations share a stamp")
	}
	if a.Stamp() == config.Stamp() {
		t.Error("an admin target shares a stamp with the same definition in config")
	}
	config.Generation = "g1"
	if config.Stamp() != baseTarget().Stamp() {
		t.Error("a generation moved a config stamp")
	}
}
