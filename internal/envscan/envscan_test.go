package envscan

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(files ...compose.File) *collect.Collected {
	return &collect.Collected{ComposeFiles: files}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(collected())
	if r.Summary.TotalVars != 0 {
		t.Fatalf("expected 0 vars, got %d", r.Summary.TotalVars)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestNoEnvVars(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "compose.yml",
		Services: []compose.Service{{Name: "app", Image: "nginx:1.25"}},
	}))
	if r.Summary.TotalVars != 0 {
		t.Errorf("expected 0 vars, got %d", r.Summary.TotalVars)
	}
}

func TestCleanEnvVars(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.25",
			Environment: []string{"PORT=8080", "HOSTNAME=myapp"},
		}},
	}))
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", r.Summary.TotalFindings, r.Findings)
	}
}

func TestDebugModeEnabled(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"DEBUG=true"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "debug_mode" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected debug_mode finding")
	}
}

func TestFlaskDebug(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "api", Image: "python:3.12",
			Environment: []string{"FLASK_DEBUG=1"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "debug_mode" && strings.Contains(f.Message, "FLASK_DEBUG") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected FLASK_DEBUG finding")
	}
}

func TestNodeEnvDevelopment(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "web", Image: "node:20",
			Environment: []string{"NODE_ENV=development"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "debug_mode" && strings.Contains(f.Message, "NODE_ENV") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NODE_ENV=development finding")
	}
}

func TestDebugModeFalseOK(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"DEBUG=false", "NODE_ENV=production"},
		}},
	}))
	for _, f := range r.Findings {
		if f.Category == "debug_mode" {
			t.Fatalf("unexpected debug_mode finding: %+v", f)
		}
	}
}

func TestInsecureHTTP(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"API_URL=http://api.example.com/v1"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "insecure_protocol" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected insecure_protocol finding")
	}
}

func TestLocalhostHTTPOK(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"API_URL=http://localhost:3000"},
		}},
	}))
	for _, f := range r.Findings {
		if f.Category == "insecure_protocol" {
			t.Fatalf("unexpected insecure_protocol finding for localhost: %+v", f)
		}
	}
}

func TestHTTPSOK(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"API_URL=https://api.example.com"},
		}},
	}))
	for _, f := range r.Findings {
		if f.Category == "insecure_protocol" {
			t.Fatalf("unexpected insecure_protocol for HTTPS: %+v", f)
		}
	}
}

func TestWeakPassword(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "db", Image: "postgres:16",
			Environment: []string{"POSTGRES_PASSWORD=password"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "weak_password" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical weak_password finding")
	}
}

func TestStrongPasswordOK(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "db", Image: "postgres:16",
			Environment: []string{"POSTGRES_PASSWORD=xK9$mR2vL8nQ4wP7"},
		}},
	}))
	for _, f := range r.Findings {
		if f.Category == "weak_password" {
			t.Fatalf("unexpected weak_password for strong password: %+v", f)
		}
	}
}

func TestEmptySecret(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"API_KEY="},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "empty_secret" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected empty_secret finding")
	}
}

func TestNodeTLSDisabled(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "tls_disabled" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical tls_disabled finding")
	}
}

func TestPythonHTTPSVerifyDisabled(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "python:3.12",
			Environment: []string{"PYTHONHTTPSVERIFY=0"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "tls_disabled" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected tls_disabled finding for PYTHONHTTPSVERIFY")
	}
}

func TestGitSSLNoVerify(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "ci", Image: "alpine/git",
			Environment: []string{"GIT_SSL_NO_VERIFY=true"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "tls_disabled" && strings.Contains(f.Message, "Git SSL") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected tls_disabled finding for GIT_SSL_NO_VERIFY")
	}
}

func TestWildcardBind(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"HOST=0.0.0.0"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Category == "wildcard_bind" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected wildcard_bind finding")
	}
}

func TestLocalBindOK(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"HOST=127.0.0.1"},
		}},
	}))
	for _, f := range r.Findings {
		if f.Category == "wildcard_bind" {
			t.Fatalf("unexpected wildcard_bind for 127.0.0.1: %+v", f)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{
				"DEBUG=true",
				"NODE_TLS_REJECT_UNAUTHORIZED=0",
				"API_URL=http://api.example.com",
				"DB_PASSWORD=password",
			},
		}},
	}))
	for i := 1; i < len(r.Findings); i++ {
		if sevRank(r.Findings[i].Severity) > sevRank(r.Findings[i-1].Severity) {
			t.Errorf("finding %d (%s) ranked higher than %d (%s)",
				i, r.Findings[i].Severity, i-1, r.Findings[i-1].Severity)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{
				"NODE_TLS_REJECT_UNAUTHORIZED=0",
				"DB_PASSWORD=password",
				"API_URL=http://api.example.com",
				"DEBUG=true",
			},
		}},
	}))
	total := r.Summary.CriticalCount + r.Summary.HighCount + r.Summary.MediumCount + r.Summary.LowCount
	if total != r.Summary.TotalFindings {
		t.Fatalf("severity counts (%d) != total findings (%d)", total, r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "node:20",
			Environment: []string{"DEBUG=true"},
		}},
	}))
	text := FormatText(r)
	if !strings.Contains(text, "Environment Variable Security Scan") {
		t.Fatal("missing header")
	}
	if !strings.Contains(text, "debug") {
		t.Fatal("missing debug mention")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(collected())
	text := FormatText(r)
	if !strings.Contains(text, "No environment variables found") {
		t.Fatal("missing empty message")
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "compose.yml",
		Services: []compose.Service{
			{Name: "web", Image: "node:20", Environment: []string{"DEBUG=1"}},
			{Name: "db", Image: "postgres:16", Environment: []string{"POSTGRES_PASSWORD=admin"}},
		},
	}))
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleFiles(t *testing.T) {
	r := Analyze(collected(
		compose.File{
			Path: "base.yml",
			Services: []compose.Service{{
				Name: "app", Image: "node:20",
				Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"},
			}},
		},
		compose.File{
			Path: "override.yml",
			Services: []compose.Service{{
				Name: "db", Image: "postgres:16",
				Environment: []string{"POSTGRES_PASSWORD=changeme"},
			}},
		},
	))
	if r.Summary.FilesChecked != 2 {
		t.Fatalf("expected 2 files checked, got %d", r.Summary.FilesChecked)
	}
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}
