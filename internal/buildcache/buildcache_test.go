package buildcache

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func TestAnalyze_CacheMounts(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM golang:1.21
RUN --mount=type=cache,target=/root/.cache/go-build go build -o app .
RUN --mount=type=cache,target=/var/cache/apt apt-get install -y curl
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	if r.Summary.FilesWithCache != 1 {
		t.Errorf("expected 1 file with cache, got %d", r.Summary.FilesWithCache)
	}
	if r.Summary.TotalMounts != 2 {
		t.Errorf("expected 2 cache mounts, got %d", r.Summary.TotalMounts)
	}

	hasSensitive := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "cache_sensitive_path" {
				hasSensitive = true
			}
		}
	}
	if !hasSensitive {
		t.Error("expected cache_sensitive_path finding for /root/.cache/go-build")
	}
}

func TestAnalyze_NoCache(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM alpine:3.18\nRUN apk add curl\n",
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)
	if r.Summary.FilesWithCache != 0 {
		t.Errorf("expected 0 files with cache, got %d", r.Summary.FilesWithCache)
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyze_RootUID(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM python:3.11
RUN --mount=type=cache,target=/var/cache/pip,uid=0 pip install -r requirements.txt
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	hasRootUID := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "cache_root_uid" {
				hasRootUID = true
			}
		}
	}
	if !hasRootUID {
		t.Error("expected cache_root_uid finding")
	}
}

func TestAnalyze_PipNoCache(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path: "Dockerfile",
				Content: `FROM python:3.11
RUN --mount=type=cache,target=/root/.cache/pip pip install flask
`,
			},
		},
	}
	c.Dockerfiles[0] = collect.ParseDockerfile("Dockerfile", c.Dockerfiles[0].Content)

	r := Analyze(c)

	hasPipNoCache := false
	for _, fr := range r.Files {
		for _, f := range fr.Findings {
			if f.RuleID == "cache_pip_no_nocache" {
				hasPipNoCache = true
			}
		}
	}
	if !hasPipNoCache {
		t.Error("expected cache_pip_no_nocache finding")
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Files: []FileResult{
			{
				Path: "Dockerfile",
				CacheMounts: []CacheMount{
					{Target: "/root/.cache", Line: 2},
				},
				Findings: []Finding{
					{File: "Dockerfile", RuleID: "cache_sensitive_path", Severity: "high", Detail: "test", Line: 2},
				},
			},
		},
		Summary: Summary{TotalFiles: 1, FilesWithCache: 1, TotalMounts: 1, TotalFindings: 1},
	}

	out := FormatText(r)
	if !strings.Contains(out, "Build Cache Security") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(out, "cache_sensitive_path") {
		t.Error("expected finding in text output")
	}
}
