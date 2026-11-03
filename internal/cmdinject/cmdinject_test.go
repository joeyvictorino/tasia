package cmdinject

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestShellFormEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"/bin/sh -c echo hello"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_shell_form") {
		t.Error("expected cmd_shell_form for shell form entrypoint")
	}
}

func TestExecFormEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"python", "-u", "main.py"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cmd_shell_form") {
		t.Error("should not flag exec form entrypoint")
	}
}

func TestEnvExpansionEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"sh", "-c", "echo $SECRET"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_env_expansion") {
		t.Error("expected cmd_env_expansion for $SECRET in entrypoint")
	}
}

func TestEnvExpansionBrace(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Command: []string{"sh", "-c", "echo ${DB_HOST}:${DB_PORT}"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_env_expansion") {
		t.Error("expected cmd_env_expansion for ${} in command")
	}
}

func TestNoEnvExpansion(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"node", "server.js"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cmd_env_expansion") {
		t.Error("should not flag entrypoint without variable expansion")
	}
}

func TestUnsafeEval(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"sh", "-c", "eval $STARTUP_CMD"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_unsafe_eval") {
		t.Error("expected cmd_unsafe_eval for eval in entrypoint")
	}
}

func TestUnsafeSource(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Command: []string{"bash", "-c", "source /tmp/config.sh && run"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_unsafe_eval") {
		t.Error("expected cmd_unsafe_eval for source in command")
	}
}

func TestNoUnsafeEval(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"python", "main.py"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cmd_unsafe_eval") {
		t.Error("should not flag clean entrypoint")
	}
}

func TestCurlPipeShell(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "setup",
		Entrypoint: []string{"sh", "-c", "curl https://example.com/install.sh | bash"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_curl_pipe") {
		t.Error("expected cmd_curl_pipe for curl piped to bash")
	}
}

func TestWgetPipeShell(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "setup",
		Command: []string{"sh", "-c", "wget -qO- https://example.com/setup.sh|sh"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_curl_pipe") {
		t.Error("expected cmd_curl_pipe for wget piped to sh")
	}
}

func TestNoCurlPipe(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"curl", "https://example.com/health"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cmd_curl_pipe") {
		t.Error("should not flag curl without pipe to shell")
	}
}

func TestWildcardGlob(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"sh", "-c", "cat /config/*.conf"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_wildcard_glob") {
		t.Error("expected cmd_wildcard_glob for *.conf pattern")
	}
}

func TestNoWildcard(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"python", "main.py"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cmd_wildcard_glob") {
		t.Error("should not flag entrypoint without wildcards")
	}
}

func TestSetuidExec(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Command: []string{"sh", "-c", "chmod u+s /usr/bin/mybin && exec mybin"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_setuid_exec") {
		t.Error("expected cmd_setuid_exec for chmod u+s")
	}
}

func TestNoSetuid(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Command: []string{"chmod", "755", "/app/bin"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cmd_setuid_exec") {
		t.Error("should not flag chmod without SUID")
	}
}

func TestCommandFieldChecked(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Command: []string{"sh", "-c", "eval $CMD"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cmd_unsafe_eval") {
		t.Error("expected cmd_unsafe_eval in command field")
	}
}

func TestNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "danger",
		Entrypoint: []string{"sh", "-c", "curl https://example.com/setup.sh | bash && eval $CMD && chmod u+s /bin/app"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"sh", "-c", "eval $CMD"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Command Injection") {
		t.Error("expected 'Command Injection' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}
