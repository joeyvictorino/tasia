package copyaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestIsSensitiveDest(t *testing.T) {
	if !isSensitiveDest("/etc/passwd") {
		t.Error("expected /etc/passwd to be sensitive")
	}
	if !isSensitiveDest("/usr/bin/app") {
		t.Error("expected /usr/bin/app to be sensitive")
	}
	if isSensitiveDest("/app/data") {
		t.Error("expected /app/data to be non-sensitive")
	}
	if isSensitiveDest("/home/user/app") {
		t.Error("expected /home/user/app to be non-sensitive")
	}
}

func TestAnalyzeDockerfileAddURL(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nADD https://example.com/file.tar.gz /app/",
		Adds: []collect.DockerfileAdd{
			{Source: "https://example.com/file.tar.gz", Dest: "/app/", IsURL: true},
		},
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "add_url_source" {
			found = true
		}
	}
	if !found {
		t.Error("expected add_url_source finding")
	}
}

func TestAnalyzeDockerfileAddSensitiveDest(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nADD config.conf /etc/nginx/",
		User:    "app",
		Adds: []collect.DockerfileAdd{
			{Source: "config.conf", Dest: "/etc/nginx/"},
		},
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "add_sensitive_dest" {
			found = true
		}
	}
	if !found {
		t.Error("expected add_sensitive_dest finding")
	}
}

func TestAnalyzeDockerfileAddAsRoot(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nADD app.tar.gz /app/",
		Adds: []collect.DockerfileAdd{
			{Source: "app.tar.gz", Dest: "/app/"},
		},
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "add_as_root" {
			found = true
		}
	}
	if !found {
		t.Error("expected add_as_root finding")
	}
}

func TestAnalyzeDockerfileNoAdds(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nCOPY app /app/",
	}
	dr := analyzeDockerfile(df)
	if len(dr.Findings) != 0 {
		t.Errorf("expected no findings for Dockerfile without ADD, got %d", len(dr.Findings))
	}
}

func TestAnalyzeDockerfileAddWithUser(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nUSER app\nADD data /data/",
		User:    "app",
		Adds: []collect.DockerfileAdd{
			{Source: "data", Dest: "/data/"},
		},
	}
	dr := analyzeDockerfile(df)
	for _, f := range dr.Findings {
		if f.Rule == "add_as_root" {
			t.Error("expected no add_as_root finding when USER is set")
		}
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{},
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM nginx\nADD https://example.com/f /etc/conf",
				Adds: []collect.DockerfileAdd{
					{Source: "https://example.com/f", Dest: "/etc/conf", IsURL: true},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM nginx\nADD app /app/",
				Adds: []collect.DockerfileAdd{
					{Source: "app", Dest: "/app/"},
				},
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "COPY/ADD Audit") {
		t.Error("expected header in text output")
	}
}

func TestSummarize(t *testing.T) {
	dockerfiles := []DockerfileResult{
		{File: "Dockerfile", Findings: []Finding{
			{Rule: "add_url_source"},
			{Rule: "add_sensitive_dest"},
			{Rule: "add_as_root"},
		}},
	}
	s := summarize(dockerfiles)
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.AddURL != 1 {
		t.Errorf("expected 1 add_url, got %d", s.AddURL)
	}
	if s.AddSensitiveDest != 1 {
		t.Errorf("expected 1 add_sensitive_dest, got %d", s.AddSensitiveDest)
	}
}
