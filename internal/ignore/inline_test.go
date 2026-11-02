package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractDisableRules(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"# tasia:disable=exposed_inference", []string{"exposed_inference"}},
		{"# tasia:disable=latest_image,privileged_container", []string{"latest_image", "privileged_container"}},
		{"// tasia:disable=tf_sg_ingress_all", []string{"tf_sg_ingress_all"}},
		{"  # tasia:disable=docker_socket_mount  # dev only", []string{"docker_socket_mount"}},
		{"    ports:", nil},
		{"tasia:disable=exposed_inference", nil}, // no comment prefix
		{"# some other comment", nil},
		{"# tasia:disable=", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got := extractDisableRules(tc.line)
		if len(got) != len(tc.want) {
			t.Errorf("extractDisableRules(%q) = %v, want %v", tc.line, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("extractDisableRules(%q)[%d] = %q, want %q", tc.line, i, got[i], tc.want[i])
			}
		}
	}
}

func TestScanInline(t *testing.T) {
	dir := t.TempDir()
	content := `services:
  ollama:
    image: ollama/ollama # tasia:disable=latest_image
    ports:
      # tasia:disable=exposed_inference
      - "11434:11434"
  webui:
    image: open-webui:latest
    ports:
      - "3000:8080"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	keys := ScanInline(dir)

	// latest_image on line 3 should suppress line 3 and 4
	if !keys[inlineKey{File: "docker-compose.yml", Line: 3, RuleID: "latest_image"}] {
		t.Error("should suppress latest_image on line 3")
	}
	if !keys[inlineKey{File: "docker-compose.yml", Line: 4, RuleID: "latest_image"}] {
		t.Error("should suppress latest_image on line 4 (next-line)")
	}

	// exposed_inference on line 5 should suppress line 5 and 6
	if !keys[inlineKey{File: "docker-compose.yml", Line: 5, RuleID: "exposed_inference"}] {
		t.Error("should suppress exposed_inference on line 5")
	}
	if !keys[inlineKey{File: "docker-compose.yml", Line: 6, RuleID: "exposed_inference"}] {
		t.Error("should suppress exposed_inference on line 6 (next-line)")
	}

	// webui on line 9 should NOT be suppressed
	if keys[inlineKey{File: "docker-compose.yml", Line: 9, RuleID: "latest_image"}] {
		t.Error("should not suppress latest_image on line 9")
	}
}

func TestScanInlineTerraform(t *testing.T) {
	dir := t.TempDir()
	content := `resource "aws_security_group" "wide_open" {
  // tasia:disable=tf_sg_ingress_all
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	keys := ScanInline(dir)
	if !keys[inlineKey{File: "main.tf", Line: 2, RuleID: "tf_sg_ingress_all"}] {
		t.Error("should suppress tf_sg_ingress_all on line 2")
	}
	if !keys[inlineKey{File: "main.tf", Line: 3, RuleID: "tf_sg_ingress_all"}] {
		t.Error("should suppress tf_sg_ingress_all on line 3 (next-line)")
	}
}

func TestScanInlineSkipsDotTasia(t *testing.T) {
	dir := t.TempDir()
	tasiaDir := filepath.Join(dir, ".tasia")
	if err := os.MkdirAll(tasiaDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tasiaDir, "findings.json"), []byte("# tasia:disable=everything\n"), 0644); err != nil {
		t.Fatal(err)
	}

	keys := ScanInline(dir)
	if len(keys) != 0 {
		t.Errorf("should skip .tasia/ directory, got %d keys", len(keys))
	}
}

func TestSuppressesAtInline(t *testing.T) {
	pol := &Policy{}
	pol.AddInline(map[inlineKey]bool{
		{File: "docker-compose.yml", Line: 5, RuleID: "exposed_inference"}: true,
	})

	if !pol.SuppressesAt("exposed_inference", "docker-compose.yml", 5) {
		t.Error("should suppress exposed_inference at line 5")
	}
	if pol.SuppressesAt("exposed_inference", "docker-compose.yml", 10) {
		t.Error("should not suppress exposed_inference at line 10")
	}
	if pol.SuppressesAt("latest_image", "docker-compose.yml", 5) {
		t.Error("should not suppress latest_image at line 5")
	}
}

func TestSuppressesAtCombinesFileAndInline(t *testing.T) {
	pol := &Policy{
		Entries: []Entry{{RuleID: "latest_image"}},
	}
	pol.AddInline(map[inlineKey]bool{
		{File: "docker-compose.yml", Line: 5, RuleID: "exposed_inference"}: true,
	})

	// .tasiaignore suppresses latest_image everywhere
	if !pol.SuppressesAt("latest_image", "docker-compose.yml", 5) {
		t.Error("should suppress latest_image via .tasiaignore")
	}
	if !pol.SuppressesAt("latest_image", "other.yml", 99) {
		t.Error("should suppress latest_image in any file via .tasiaignore")
	}

	// Inline suppresses exposed_inference only at line 5
	if !pol.SuppressesAt("exposed_inference", "docker-compose.yml", 5) {
		t.Error("should suppress exposed_inference at line 5 via inline")
	}
	if pol.SuppressesAt("exposed_inference", "docker-compose.yml", 10) {
		t.Error("should not suppress exposed_inference at line 10")
	}
}

func TestIsScannableFile(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{".env", true},
		{".env.local", true},
		{"main.tf", true},
		{"Dockerfile", true},
		{"Dockerfile.prod", true},
		{"Caddyfile", true},
		{"nginx.conf", true},
		{"README.md", false},
		{"main.go", false},
		{"package.json", false},
	}
	for _, tc := range cases {
		if got := isScannableFile(tc.name); got != tc.want {
			t.Errorf("isScannableFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScanInlineMultiRule(t *testing.T) {
	dir := t.TempDir()
	content := `# tasia:disable=latest_image,permissive_cors
services:
  ollama:
    image: ollama/ollama
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	keys := ScanInline(dir)
	if !keys[inlineKey{File: "docker-compose.yml", Line: 1, RuleID: "latest_image"}] {
		t.Error("should suppress latest_image on line 1")
	}
	if !keys[inlineKey{File: "docker-compose.yml", Line: 1, RuleID: "permissive_cors"}] {
		t.Error("should suppress permissive_cors on line 1")
	}
	if !keys[inlineKey{File: "docker-compose.yml", Line: 2, RuleID: "latest_image"}] {
		t.Error("should suppress latest_image on line 2 (next-line)")
	}
}
