package workdir

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

func TestMissingWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nRUN echo hello")))
	if r.Summary.MissingWorkdir != 1 {
		t.Fatalf("want 1 missing, got %d", r.Summary.MissingWorkdir)
	}
	if r.Files[0].Findings[0].RuleID != "workdir_missing" {
		t.Fatalf("want workdir_missing, got %s", r.Files[0].Findings[0].RuleID)
	}
}

func TestGoodWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR /app\nRUN echo hello")))
	if r.Summary.MissingWorkdir != 0 {
		t.Fatalf("want 0 missing, got %d", r.Summary.MissingWorkdir)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("want 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestTmpWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR /tmp")))
	if r.Summary.TmpWorkdir != 1 {
		t.Fatalf("want 1 tmp, got %d", r.Summary.TmpWorkdir)
	}
	if r.Files[0].Findings[0].RuleID != "workdir_tmp" {
		t.Fatalf("want workdir_tmp, got %s", r.Files[0].Findings[0].RuleID)
	}
}

func TestVarTmpWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR /var/tmp")))
	if r.Summary.TmpWorkdir != 1 {
		t.Fatalf("want 1 tmp, got %d", r.Summary.TmpWorkdir)
	}
}

func TestRootWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR /")))
	if r.Summary.RootWorkdir != 1 {
		t.Fatalf("want 1 root, got %d", r.Summary.RootWorkdir)
	}
}

func TestRootHomeWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR /root")))
	if r.Summary.RootWorkdir != 1 {
		t.Fatalf("want 1 root, got %d", r.Summary.RootWorkdir)
	}
}

func TestRelativeWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR app")))
	found := false
	for _, f := range r.Files[0].Findings {
		if f.RuleID == "workdir_relative" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected workdir_relative finding")
	}
}

func TestEnvVarWorkdir(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR $APP_DIR")))
	for _, f := range r.Files[0].Findings {
		if f.RuleID == "workdir_relative" {
			t.Fatal("env var workdir should not be flagged as relative")
		}
	}
}

func TestMultipleDockerfiles(t *testing.T) {
	r := Analyze(collected(
		df("Dockerfile.a", "FROM alpine\nWORKDIR /tmp"),
		df("Dockerfile.b", "FROM ubuntu\nWORKDIR /app"),
	))
	if r.Summary.TotalFiles != 2 {
		t.Fatalf("want 2, got %d", r.Summary.TotalFiles)
	}
	if r.Summary.TmpWorkdir != 1 {
		t.Fatalf("want 1 tmp, got %d", r.Summary.TmpWorkdir)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(df("Dockerfile", "FROM alpine\nWORKDIR /tmp")))
	text := FormatText(r)
	if !strings.Contains(text, "WORKDIR Security") {
		t.Fatal("should contain header")
	}
	if !strings.Contains(text, "workdir_tmp") {
		t.Fatal("should contain rule id")
	}
}
