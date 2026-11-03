package nonroot

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestIsRootUser(t *testing.T) {
	if !isRootUser("root") {
		t.Error("expected root detected")
	}
	if !isRootUser("0") {
		t.Error("expected uid 0 detected")
	}
	if !isRootUser("0:0") {
		t.Error("expected 0:0 detected")
	}
	if isRootUser("appuser") {
		t.Error("expected non-root for appuser")
	}
	if isRootUser("1000") {
		t.Error("expected non-root for uid 1000")
	}
}

func TestAnalyzeServiceNoUser(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "no_user_directive" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_user_directive finding")
	}
}

func TestAnalyzeServiceExplicitRoot(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx", User: "root"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "explicit_root_user" {
			found = true
		}
	}
	if !found {
		t.Error("expected explicit_root_user finding")
	}
}

func TestAnalyzeServiceNonRoot(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx", User: "appuser"}
	sr := analyzeService(svc, "docker-compose.yml")
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings for non-root user, got %d", len(sr.Findings))
	}
}

func TestAnalyzeServicePrivilegedRoot(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx", Privileged: true}
	sr := analyzeService(svc, "docker-compose.yml")
	foundPriv := false
	for _, f := range sr.Findings {
		if f.Rule == "privileged_root" {
			foundPriv = true
		}
	}
	if !foundPriv {
		t.Error("expected privileged_root finding")
	}
}

func TestAnalyzeDockerfileNoUser(t *testing.T) {
	df := collect.Dockerfile{Path: "Dockerfile", Content: "FROM nginx"}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "dockerfile_no_user" {
			found = true
		}
	}
	if !found {
		t.Error("expected dockerfile_no_user finding")
	}
}

func TestAnalyzeDockerfileRootUser(t *testing.T) {
	df := collect.Dockerfile{Path: "Dockerfile", Content: "FROM nginx\nUSER root", User: "root"}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "dockerfile_root_user" {
			found = true
		}
	}
	if !found {
		t.Error("expected dockerfile_root_user finding")
	}
}

func TestAnalyzeDockerfileNonRoot(t *testing.T) {
	df := collect.Dockerfile{Path: "Dockerfile", Content: "FROM nginx\nUSER app", User: "app"}
	dr := analyzeDockerfile(df)
	if len(dr.Findings) != 0 {
		t.Errorf("expected no findings for non-root, got %d", len(dr.Findings))
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx"},
					{Name: "api", Image: "myapp", User: "app"},
				},
			},
		},
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM nginx"},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path:     "docker-compose.yml",
				Services: []compose.Service{{Name: "svc1", Image: "nginx"}},
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Non-Root") {
		t.Error("expected header in text output")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{Service: "a", Findings: []Finding{{Rule: "no_user_directive"}, {Rule: "privileged_root"}}},
	}
	dockerfiles := []DockerfileResult{
		{File: "Dockerfile", Findings: []Finding{{Rule: "dockerfile_no_user"}}},
	}
	s := summarize(services, dockerfiles)
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.NoUserSet != 2 {
		t.Errorf("expected 2 no_user_set, got %d", s.NoUserSet)
	}
	if s.PrivilegedRoot != 1 {
		t.Errorf("expected 1 privileged_root, got %d", s.PrivilegedRoot)
	}
}
