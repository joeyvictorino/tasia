package credscan

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeClean(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM nginx:latest\nRUN apt-get update\n"},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.Score != 100 {
		t.Fatalf("expected score 100, got %d", r.Summary.Score)
	}
}

func TestAnalyzeDockerfileAWSKey(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM python:3.11\nENV AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for AWS key")
	}
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.RuleID, "aws_access_key") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected aws_access_key finding")
	}
}

func TestAnalyzeDockerfilePrivateKey(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM alpine\nRUN echo '-----BEGIN RSA PRIVATE KEY-----'\n"},
		},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.RuleID, "private_key") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected private_key finding")
	}
}

func TestAnalyzeComposeSecret(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "api",
						Image:       "myapp:latest",
						Environment: []string{"DATABASE_URL=postgres://user:secretpass@db:5432/app"},
					},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for database URL with credentials")
	}
}

func TestAnalyzeEnvFilePattern(t *testing.T) {
	c := &collect.Collected{
		EnvFiles: []collect.EnvFile{
			{
				Path: ".env",
				Keys: []collect.EnvKey{
					{Name: "API_TOKEN", Line: 3, ValuePattern: "sk- prefix"},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected finding for env secret pattern")
	}
	if r.Findings[0].RuleID != "cred_env_secret_pattern" {
		t.Fatalf("expected cred_env_secret_pattern, got %s", r.Findings[0].RuleID)
	}
}

func TestScoreDecreasesWithFindings(t *testing.T) {
	c := &collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM alpine\nENV SECRET=AKIAIOSFODNN7EXAMPLE\nENV TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl\n"},
		},
	}
	r := Analyze(c)
	if r.Summary.Score >= 100 {
		t.Fatalf("expected score < 100, got %d", r.Summary.Score)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Report{Summary: Summary{Score: 100}}
	out := FormatText(r)
	if !strings.Contains(out, "Credential Scan Report") {
		t.Fatal("expected header")
	}
	if !strings.Contains(out, "No credential leaks") {
		t.Fatal("expected clean message")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	r := Report{
		Findings: []CredentialFinding{
			{File: "Dockerfile", Line: 5, RuleID: "cred_test", Severity: "high", Pattern: "test", Context: "test context", Remediation: "fix it"},
		},
		Summary: Summary{TotalFindings: 1, HighSeverity: 1, Score: 80},
	}
	out := FormatText(r)
	if !strings.Contains(out, "HIGH") {
		t.Fatal("expected HIGH in output")
	}
	if !strings.Contains(out, "Dockerfile:5") {
		t.Fatal("expected file:line in output")
	}
}

func TestTruncateContext(t *testing.T) {
	short := "short string"
	if truncateContext(short) != short {
		t.Fatal("short string should not be truncated")
	}
	long := strings.Repeat("a", 100)
	result := truncateContext(long)
	if len(result) > 80 {
		t.Fatalf("expected truncated to 80, got %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Fatal("expected ... suffix")
	}
}
