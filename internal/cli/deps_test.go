package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDepsEmpty(t *testing.T) {
	dir := t.TempDir()
	err := runDeps([]string{"--path", dir})
	if err != nil {
		t.Fatalf("deps empty: %v", err)
	}
}

func TestDepsJSON(t *testing.T) {
	dir := t.TempDir()
	err := runDeps([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDepsWithImages(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  web:
    image: nginx:1.25.3
  db:
    image: postgres:latest
  cache:
    image: redis
  pinned:
    image: myapp@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
`), 0644)

	err := runDeps([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		ref, image, tag string
	}{
		{"nginx:1.25", "nginx", "1.25"},
		{"nginx:latest", "nginx", "latest"},
		{"nginx", "nginx", ""},
		{"myrepo/app:v2.1.0", "myrepo/app", "v2.1.0"},
		{"myapp@sha256:abcd", "myapp", "sha256:abcd"},
		{"registry.io/org/app:3.0", "registry.io/org/app", "3.0"},
	}
	for _, tt := range tests {
		img, tag := parseImageRef(tt.ref)
		if img != tt.image || tag != tt.tag {
			t.Errorf("parseImageRef(%q) = (%q, %q), want (%q, %q)", tt.ref, img, tag, tt.image, tt.tag)
		}
	}
}

func TestIsSemverTag(t *testing.T) {
	if !isSemverTag("1.25.3") {
		t.Error("expected 1.25.3 to be semver")
	}
	if !isSemverTag("v2.1.0") {
		t.Error("expected v2.1.0 to be semver")
	}
	if isSemverTag("latest") {
		t.Error("expected latest to not be semver")
	}
	if isSemverTag("") {
		t.Error("expected empty to not be semver")
	}
}

func TestAssessDep(t *testing.T) {
	e := depEntry{IsLatest: true}
	risk, _ := assessDep(e)
	if risk != "high" {
		t.Errorf("expected high risk for :latest, got %s", risk)
	}

	e2 := depEntry{HasNoTag: true}
	risk2, _ := assessDep(e2)
	if risk2 != "high" {
		t.Errorf("expected high risk for no tag, got %s", risk2)
	}

	e3 := depEntry{IsDigest: true}
	risk3, _ := assessDep(e3)
	if risk3 != "low" {
		t.Errorf("expected low risk for digest, got %s", risk3)
	}
}
