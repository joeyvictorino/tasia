package secretscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFileContentAWSKey(t *testing.T) {
	content := `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`
	findings := ScanFileContent(content, "test.env")
	if len(findings) == 0 {
		t.Fatal("expected findings for AWS access key")
	}
	found := false
	for _, f := range findings {
		if f.Pattern == "aws_access_key" {
			found = true
		}
	}
	if !found {
		t.Error("expected aws_access_key pattern match")
	}
}

func TestScanFileContentGitHubToken(t *testing.T) {
	content := `GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
	findings := ScanFileContent(content, "test.env")
	found := false
	for _, f := range findings {
		if f.Pattern == "github_token" {
			found = true
		}
	}
	if !found {
		t.Error("expected github_token pattern match")
	}
}

func TestScanFileContentPasswordInURL(t *testing.T) {
	content := `DATABASE_URL=postgres://admin:s3cretPass@db.example.com:5432/app`
	findings := ScanFileContent(content, "test.env")
	found := false
	for _, f := range findings {
		if f.Pattern == "password_in_url" || f.Pattern == "database_connection_string" {
			found = true
		}
	}
	if !found {
		t.Error("expected password_in_url or database_connection_string match")
	}
}

func TestScanFileContentPrivateKey(t *testing.T) {
	content := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
	findings := ScanFileContent(content, "key.pem")
	found := false
	for _, f := range findings {
		if f.Pattern == "private_key" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("expected private_key pattern match with critical severity")
	}
}

func TestScanFileContentJWT(t *testing.T) {
	content := `AUTH_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`
	findings := ScanFileContent(content, "config.yaml")
	found := false
	for _, f := range findings {
		if f.Pattern == "jwt_token" {
			found = true
		}
	}
	if !found {
		t.Error("expected jwt_token pattern match")
	}
}

func TestScanFileContentOpenAI(t *testing.T) {
	content := `OPENAI_API_KEY=sk-proj1234567890abcdefghij`
	findings := ScanFileContent(content, ".env")
	found := false
	for _, f := range findings {
		if f.Pattern == "openai_api_key" {
			found = true
		}
	}
	if !found {
		t.Error("expected openai_api_key pattern match")
	}
}

func TestScanFileContentNoSecrets(t *testing.T) {
	content := `PORT=8080
HOST=localhost
DEBUG=true`
	findings := ScanFileContent(content, "config.env")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe content, got %d", len(findings))
	}
}

func TestMaskValue(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "AKIA****"},
		{"abc", "****"},
		{"sk-1234567890", "sk-1****"},
	}
	for _, tc := range cases {
		got := maskValue(tc.input)
		if got != tc.want {
			t.Errorf("maskValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestScanDirectory(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	os.WriteFile(envFile, []byte("SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n"), 0644)
	safeFile := filepath.Join(dir, "readme.md")
	os.WriteFile(safeFile, []byte("# Readme\n"), 0644)

	result, err := ScanDirectory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalFiles != 1 {
		t.Errorf("expected 1 scannable file, got %d", result.TotalFiles)
	}
	if result.SecretsFound == 0 {
		t.Error("expected to find secrets in .env")
	}
}

func TestScanDirectoryRecursive(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "configs")
	os.MkdirAll(subdir, 0755)
	os.WriteFile(filepath.Join(subdir, "app.yaml"), []byte("api_key: sk-proj1234567890abcdefghij\n"), 0644)

	result, err := ScanDirectory(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.SecretsFound == 0 {
		t.Error("expected to find secrets recursively")
	}
}

func TestFormatText(t *testing.T) {
	r := ScanResult{
		TotalFiles:   5,
		SecretsFound: 2,
		BySeverity:   map[string]int{"critical": 1, "high": 1},
		ByType:       map[string]int{"api_key": 1, "token": 1},
		Findings: []SecretFinding{
			{File: "test.env", Line: 1, Type: "api_key", Pattern: "aws_access_key", Severity: "critical", Masked: "AKIA****"},
		},
	}
	out := FormatText(r)
	if !strings.Contains(out, "5 files scanned") {
		t.Error("expected file count in output")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected severity in output")
	}
}

func TestFormatTextNoSecrets(t *testing.T) {
	r := ScanResult{TotalFiles: 3, BySeverity: map[string]int{}, ByType: map[string]int{}}
	out := FormatText(r)
	if !strings.Contains(out, "No secrets detected") {
		t.Error("expected no-secrets message")
	}
}

func TestIsScannableFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{".env", true},
		{".env.production", true},
		{"config.yaml", true},
		{"docker-compose.yml", true},
		{"Dockerfile", true},
		{"main.go", false},
		{"readme.md", false},
		{"app.tf", true},
	}
	for _, tc := range cases {
		got := isScannableFile(tc.path)
		if got != tc.want {
			t.Errorf("isScannableFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestTruncateLine(t *testing.T) {
	short := "short line"
	if truncateLine(short, 120) != short {
		t.Error("short line should not be truncated")
	}
	long := strings.Repeat("x", 200)
	result := truncateLine(long, 120)
	if len(result) != 123 { // 120 + "..."
		t.Errorf("expected truncated length 123, got %d", len(result))
	}
}
