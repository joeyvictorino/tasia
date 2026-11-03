package layertrust

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func makeCollected(path, content string) *collect.Collected {
	df := collect.ParseDockerfile(path, content)
	return &collect.Collected{Dockerfiles: []collect.Dockerfile{df}}
}

func TestAnalyze_Empty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalDockerfiles != 0 {
		t.Fatalf("expected 0 dockerfiles, got %d", r.Summary.TotalDockerfiles)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyze_TrustedBase(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12-slim\nRUN pip install flask\n")
	r := Analyze(c)
	if len(r.Dockerfiles) != 1 {
		t.Fatalf("expected 1 dockerfile, got %d", len(r.Dockerfiles))
	}
	if r.Dockerfiles[0].BaseTrust != string(Trusted) {
		t.Fatalf("expected trusted base, got %s", r.Dockerfiles[0].BaseTrust)
	}
	if r.Dockerfiles[0].BaseImage != "python:3.12-slim" {
		t.Fatalf("expected python:3.12-slim, got %s", r.Dockerfiles[0].BaseImage)
	}
}

func TestAnalyze_UnpinnedBase(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM ubuntu\nRUN apt-get update\n")
	r := Analyze(c)
	if r.Dockerfiles[0].BaseTrust != string(Suspicious) {
		t.Fatalf("expected suspicious for untagged base, got %s", r.Dockerfiles[0].BaseTrust)
	}
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_unpinned_base" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected layer_unpinned_base finding")
	}
}

func TestAnalyze_LatestTag(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM nginx:latest\n")
	r := Analyze(c)
	if r.Dockerfiles[0].BaseTrust != string(Suspicious) {
		t.Fatalf("expected suspicious for :latest, got %s", r.Dockerfiles[0].BaseTrust)
	}
}

func TestAnalyze_DigestPinned(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python@sha256:abcdef1234567890\nRUN echo hi\n")
	r := Analyze(c)
	if r.Dockerfiles[0].BaseTrust != string(Trusted) {
		t.Fatalf("expected trusted for digest-pinned, got %s", r.Dockerfiles[0].BaseTrust)
	}
}

func TestAnalyze_UntrustedRegistry(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM evil.registry.io/malware:1.0\n")
	r := Analyze(c)
	if r.Dockerfiles[0].BaseTrust != string(Untrusted) {
		t.Fatalf("expected untrusted for unknown registry, got %s", r.Dockerfiles[0].BaseTrust)
	}
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_untrusted_registry" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected layer_untrusted_registry finding")
	}
}

func TestAnalyze_TrustedRegistries(t *testing.T) {
	registries := []string{
		"docker.io/library/ubuntu:22.04",
		"ghcr.io/org/image:1.0",
		"gcr.io/project/image:latest",
		"mcr.microsoft.com/dotnet:8.0",
		"quay.io/org/image:v1",
	}
	for _, img := range registries {
		c := makeCollected("Dockerfile", "FROM "+img+"\n")
		r := Analyze(c)
		untrustedReg := false
		for _, f := range r.Dockerfiles[0].Findings {
			if f.RuleID == "layer_untrusted_registry" {
				untrustedReg = true
			}
		}
		if untrustedReg {
			t.Errorf("registry in %q should be trusted", img)
		}
	}
}

func TestAnalyze_ScratchBase(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM scratch\nCOPY app /app\n")
	r := Analyze(c)
	if r.Dockerfiles[0].BaseTrust != string(Trusted) {
		t.Fatalf("expected trusted for scratch, got %s", r.Dockerfiles[0].BaseTrust)
	}
}

func TestAnalyze_SecretCopied(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nCOPY private.key /app/\n")
	r := Analyze(c)
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_secret_added" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected layer_secret_added finding for .key file")
	}
}

func TestAnalyze_SecretPatterns(t *testing.T) {
	patterns := []string{
		"COPY cert.pem /etc/ssl/",
		"ADD id_rsa /root/.ssh/",
		"COPY .env /app/",
		"COPY credentials.json /app/",
	}
	for _, line := range patterns {
		c := makeCollected("Dockerfile", "FROM python:3.12\n"+line+"\n")
		r := Analyze(c)
		found := false
		for _, f := range r.Dockerfiles[0].Findings {
			if f.RuleID == "layer_secret_added" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected layer_secret_added for %q", line)
		}
	}
}

func TestAnalyze_AddURL(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nADD https://example.com/installer.sh /tmp/\n")
	r := Analyze(c)
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_add_url" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected layer_add_url finding")
	}
}

func TestAnalyze_NonStandardRepo(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nRUN curl -fsSL https://get.docker.com | sh\n")
	r := Analyze(c)
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_nonstandard_repo" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected layer_nonstandard_repo finding for curl -fsSL")
	}
}

func TestAnalyze_WidePermissions(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nRUN chmod 777 /app\n")
	r := Analyze(c)
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_wide_permissions" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected layer_wide_permissions finding")
	}
}

func TestAnalyze_InsecureDownload(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nRUN wget --no-check-certificate https://example.com/file\n")
	r := Analyze(c)
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_insecure_download" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected layer_insecure_download finding")
	}
}

func TestAnalyze_EnvSecret(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nENV API_KEY=supersecret123\n")
	r := Analyze(c)
	found := false
	for _, f := range r.Dockerfiles[0].Findings {
		if f.RuleID == "layer_env_secret" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected layer_env_secret finding")
	}
}

func TestAnalyze_EnvSecretVariants(t *testing.T) {
	envs := []string{
		"ENV DB_PASSWORD=hunter2",
		"ENV SECRET_TOKEN=abc123",
		"ENV PRIVATE_KEY=mykey",
	}
	for _, env := range envs {
		c := makeCollected("Dockerfile", "FROM python:3.12\n"+env+"\n")
		r := Analyze(c)
		found := false
		for _, f := range r.Dockerfiles[0].Findings {
			if f.RuleID == "layer_env_secret" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected layer_env_secret for %q", env)
		}
	}
}

func TestAnalyze_CleanDockerfile(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12-slim\nRUN pip install flask\nCOPY app.py /app/\n")
	r := Analyze(c)
	if len(r.Dockerfiles[0].Findings) != 0 {
		t.Fatalf("expected 0 findings for clean dockerfile, got %d", len(r.Dockerfiles[0].Findings))
	}
}

func TestAnalyze_LayerCount(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nRUN pip install flask\nCOPY app.py /app/\nRUN chmod 644 /app/app.py\n")
	r := Analyze(c)
	if r.Dockerfiles[0].TotalLayers != 4 {
		t.Fatalf("expected 4 layers, got %d", r.Dockerfiles[0].TotalLayers)
	}
}

func TestAnalyze_MultipleDockerfiles(t *testing.T) {
	df1 := collect.ParseDockerfile("Dockerfile.app", "FROM python:3.12\nCOPY .env /app/\n")
	df2 := collect.ParseDockerfile("Dockerfile.web", "FROM nginx:latest\n")
	c := &collect.Collected{Dockerfiles: []collect.Dockerfile{df1, df2}}
	r := Analyze(c)
	if r.Summary.TotalDockerfiles != 2 {
		t.Fatalf("expected 2 dockerfiles, got %d", r.Summary.TotalDockerfiles)
	}
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummary_Counts(t *testing.T) {
	df1 := collect.ParseDockerfile("Dockerfile", "FROM evil.example.com/image:1.0\nRUN chmod 777 /tmp\nCOPY secret.pem /etc/\n")
	c := &collect.Collected{Dockerfiles: []collect.Dockerfile{df1}}
	r := Analyze(c)
	if r.Summary.UntrustedBases != 1 {
		t.Fatalf("expected 1 untrusted base, got %d", r.Summary.UntrustedBases)
	}
	if r.Summary.SuspiciousLayers < 2 {
		t.Fatalf("expected at least 2 suspicious layers, got %d", r.Summary.SuspiciousLayers)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM evil.registry.io/bad:1.0\nCOPY secret.key /app/\n")
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text returned empty")
	}
	if !containsStr(text, "Image Layer Trust") {
		t.Error("missing header")
	}
	if !containsStr(text, "evil.registry.io") {
		t.Error("missing registry reference")
	}
}

func TestFormatText_Clean(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nRUN pip install flask\n")
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "0 findings") {
		t.Error("expected 0 findings in output")
	}
}

func TestJSON_Roundtrip(t *testing.T) {
	c := makeCollected("Dockerfile", "FROM python:3.12\nCOPY .env /app/\n")
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if r2.Summary.TotalFindings != r.Summary.TotalFindings {
		t.Fatalf("roundtrip mismatch: %d vs %d", r2.Summary.TotalFindings, r.Summary.TotalFindings)
	}
}

func TestExtractRegistry(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{"python:3.12", ""},
		{"ubuntu", ""},
		{"ghcr.io/org/image:1.0", "ghcr.io"},
		{"evil.registry.io/image:latest", "evil.registry.io"},
		{"gcr.io/project/image@sha256:abc", "gcr.io"},
	}
	for _, tt := range tests {
		got := extractRegistry(tt.image)
		if got != tt.want {
			t.Errorf("extractRegistry(%q) = %q, want %q", tt.image, got, tt.want)
		}
	}
}

func TestExtractTag(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{"python:3.12", "3.12"},
		{"ubuntu", ""},
		{"nginx:latest", "latest"},
		{"python@sha256:abc", "pinned-digest"},
	}
	for _, tt := range tests {
		got := extractTag(tt.image)
		if got != tt.want {
			t.Errorf("extractTag(%q) = %q, want %q", tt.image, got, tt.want)
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && findSubstr(s, substr))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
