package ignore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func writeTmp(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), ".tasiaignore")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseEmpty(t *testing.T) {
	f := writeTmp(t, "")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(p.Entries))
	}
}

func TestParseCommentsAndBlanks(t *testing.T) {
	f := writeTmp(t, "# full-line comment\n\n  # indented comment\n")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(p.Entries))
	}
}

func TestParseRuleIDOnly(t *testing.T) {
	f := writeTmp(t, "exposed_inference\nlatest_image\n")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(p.Entries))
	}
	if p.Entries[0].RuleID != "exposed_inference" || p.Entries[0].FilePattern != "" {
		t.Errorf("entry 0: %+v", p.Entries[0])
	}
	if p.Entries[1].RuleID != "latest_image" || p.Entries[1].FilePattern != "" {
		t.Errorf("entry 1: %+v", p.Entries[1])
	}
}

func TestParseFilePatternOnly(t *testing.T) {
	f := writeTmp(t, "docker-compose.dev.yml\nexamples/*\n")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(p.Entries))
	}
	if p.Entries[0].FilePattern != "docker-compose.dev.yml" || p.Entries[0].RuleID != "" {
		t.Errorf("entry 0: %+v", p.Entries[0])
	}
	if p.Entries[1].FilePattern != "examples/*" || p.Entries[1].RuleID != "" {
		t.Errorf("entry 1: %+v", p.Entries[1])
	}
}

func TestParseRuleAndFile(t *testing.T) {
	f := writeTmp(t, "exposed_inference docker-compose.dev.yml\n")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(p.Entries))
	}
	e := p.Entries[0]
	if e.RuleID != "exposed_inference" || e.FilePattern != "docker-compose.dev.yml" {
		t.Errorf("entry: %+v", e)
	}
}

func TestParseFileAndRuleReversed(t *testing.T) {
	f := writeTmp(t, "docker-compose.dev.yml exposed_inference\n")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(p.Entries))
	}
	e := p.Entries[0]
	if e.RuleID != "exposed_inference" || e.FilePattern != "docker-compose.dev.yml" {
		t.Errorf("entry: %+v", e)
	}
}

func TestParseInlineComment(t *testing.T) {
	f := writeTmp(t, "exposed_inference  # dev only, don't care\n")
	defer f.Close()
	p, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(p.Entries))
	}
	if p.Entries[0].RuleID != "exposed_inference" {
		t.Errorf("entry: %+v", p.Entries[0])
	}
}

func TestSuppressesRuleEverywhere(t *testing.T) {
	p := &Policy{Entries: []Entry{{RuleID: "exposed_inference"}}}
	if !p.Suppresses("exposed_inference", "docker-compose.yml") {
		t.Error("should suppress exposed_inference in any file")
	}
	if p.Suppresses("latest_image", "docker-compose.yml") {
		t.Error("should not suppress latest_image")
	}
}

func TestSuppressesFileEverywhere(t *testing.T) {
	p := &Policy{Entries: []Entry{{FilePattern: "docker-compose.dev.yml"}}}
	if !p.Suppresses("exposed_inference", "docker-compose.dev.yml") {
		t.Error("should suppress any rule in dev compose")
	}
	if p.Suppresses("exposed_inference", "docker-compose.yml") {
		t.Error("should not suppress in main compose")
	}
}

func TestSuppressesRuleInFile(t *testing.T) {
	p := &Policy{Entries: []Entry{{RuleID: "exposed_inference", FilePattern: "docker-compose.dev.yml"}}}
	if !p.Suppresses("exposed_inference", "docker-compose.dev.yml") {
		t.Error("should suppress exposed_inference in dev compose")
	}
	if p.Suppresses("exposed_inference", "docker-compose.yml") {
		t.Error("should not suppress exposed_inference in main compose")
	}
	if p.Suppresses("latest_image", "docker-compose.dev.yml") {
		t.Error("should not suppress latest_image in dev compose")
	}
}

func TestSuppressesGlob(t *testing.T) {
	p := &Policy{Entries: []Entry{{FilePattern: "examples/*"}}}
	if !p.Suppresses("exposed_inference", "examples/docker-compose.yml") {
		t.Error("should suppress findings in examples/*")
	}
	if p.Suppresses("exposed_inference", "docker-compose.yml") {
		t.Error("should not suppress findings outside examples/")
	}
}

func TestLoadMissing(t *testing.T) {
	p, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 {
		t.Error("missing file should give empty policy")
	}
	if p.Suppresses("anything", "anywhere") {
		t.Error("empty policy should never suppress")
	}
}

func TestLoadPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".tasiaignore"), []byte("exposed_inference\n"), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(p.Entries))
	}
}

func TestIntegrationIgnoreSuppressesKitchenSink(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "kitchensink"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := collect.WalkAndCollect(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	allFindings := rules.Evaluate(c)
	if len(allFindings) == 0 {
		t.Fatal("kitchensink should produce findings")
	}

	// Suppress exposed_inference everywhere
	pol := &Policy{Entries: []Entry{{RuleID: "exposed_inference"}}}
	var filtered []rules.Finding
	for _, f := range allFindings {
		if !pol.Suppresses(f.ID, f.File) {
			filtered = append(filtered, f)
		}
	}
	for _, f := range filtered {
		if f.ID == "exposed_inference" {
			t.Error("exposed_inference should have been suppressed")
		}
	}
	if len(filtered) >= len(allFindings) {
		t.Error("filtering should have reduced the number of findings")
	}

	// Suppress only in a specific file
	pol2 := &Policy{Entries: []Entry{{RuleID: "latest_image", FilePattern: "docker-compose.yml"}}}
	var filtered2 []rules.Finding
	for _, f := range allFindings {
		if !pol2.Suppresses(f.ID, f.File) {
			filtered2 = append(filtered2, f)
		}
	}
	for _, f := range filtered2 {
		if f.ID == "latest_image" && f.File == "docker-compose.yml" {
			t.Error("latest_image in docker-compose.yml should have been suppressed")
		}
	}
}

func TestLooksLikeRuleID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"exposed_inference", true},
		{"latest_image", true},
		{"docker_socket_mount", true},
		{"docker-compose.yml", false},
		{"examples/*", false},
		{"Dockerfile", false},
		{"", false},
		{"EXPOSED_INFERENCE", false},
	}
	for _, tc := range cases {
		if got := looksLikeRuleID(tc.in); got != tc.want {
			t.Errorf("looksLikeRuleID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
