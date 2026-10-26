package main

import (
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
