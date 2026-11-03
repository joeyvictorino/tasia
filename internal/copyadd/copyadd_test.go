package copyadd

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func df(path, content string) collect.Dockerfile {
	return collect.ParseDockerfile(path, content)
}

func collected(dfs ...collect.Dockerfile) *collect.Collected {
	return &collect.Collected{Dockerfiles: dfs}
}

func TestNoDockerfiles(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("want 0, got %d", r.Summary.TotalFindings)
	}
}

func TestNoAdd(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nCOPY . /app")))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("want 0, got %d", r.Summary.TotalFindings)
	}
}

func TestAddFromURL(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD https://example.com/app.tar.gz /opt/")))
	if r.Summary.AddFromURL != 1 {
		t.Fatalf("want 1 url add, got %d", r.Summary.AddFromURL)
	}
	found := false
	for _, f := range r.Files[0].Findings {
		if f.RuleID == "add_url" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected add_url finding")
	}
}

func TestAddArchive(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD app.tar.gz /opt/")))
	if r.Summary.AddArchive != 1 {
		t.Fatalf("want 1 archive add, got %d", r.Summary.AddArchive)
	}
}

func TestAddNonArchive(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD config.json /app/")))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("want 0 findings for non-archive ADD, got %d", r.Summary.TotalFindings)
	}
}

func TestAddTarBz2(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD data.tar.bz2 /data/")))
	if r.Summary.AddArchive != 1 {
		t.Fatalf("want 1, got %d", r.Summary.AddArchive)
	}
}

func TestAddZip(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD bundle.zip /opt/")))
	if r.Summary.AddArchive != 1 {
		t.Fatalf("want 1, got %d", r.Summary.AddArchive)
	}
}

func TestHttpURL(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD http://example.com/script.sh /usr/local/bin/")))
	if r.Summary.AddFromURL != 1 {
		t.Fatalf("want 1, got %d", r.Summary.AddFromURL)
	}
}

func TestMultipleDockerfiles(t *testing.T) {
	r := Analyze(collected(
		df("Dockerfile.a", "FROM alpine\nADD https://x.com/a /a"),
		df("Dockerfile.b", "FROM ubuntu\nADD data.tar.gz /data"),
	))
	if r.Summary.TotalFiles != 2 {
		t.Fatalf("want 2, got %d", r.Summary.TotalFiles)
	}
	if r.Summary.TotalFindings != 2 {
		t.Fatalf("want 2, got %d", r.Summary.TotalFindings)
	}
}

func TestIsArchive(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"app.tar", true},
		{"app.tar.gz", true},
		{"app.tgz", true},
		{"app.tar.bz2", true},
		{"app.tar.xz", true},
		{"app.zip", true},
		{"app.json", false},
		{"app.py", false},
	}
	for _, tt := range tests {
		got := isArchive(tt.name)
		if got != tt.want {
			t.Errorf("isArchive(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nADD https://x.com/a /a")))
	text := FormatText(r)
	if !strings.Contains(text, "COPY/ADD") {
		t.Fatal("should contain header")
	}
	if !strings.Contains(text, "add_url") {
		t.Fatal("should contain rule id")
	}
}
