package execguard

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestHasPipeOrChain(t *testing.T) {
	if !hasPipeOrChain("RUN curl -s https://example.com | sh") {
		t.Error("expected pipe detected in RUN")
	}
	if !hasPipeOrChain("RUN cmd1 && cmd2") {
		t.Error("expected chain detected in RUN")
	}
	if hasPipeOrChain("RUN apt-get update") {
		t.Error("expected no pipe/chain in simple RUN")
	}
	if hasPipeOrChain("COPY . /app") {
		t.Error("expected no pipe/chain in non-RUN instruction")
	}
}

func TestHasUnsafeShellExpansion(t *testing.T) {
	if !hasUnsafeShellExpansion("RUN echo $(whoami)") {
		t.Error("expected $() detected in RUN")
	}
	if !hasUnsafeShellExpansion("RUN echo `date`") {
		t.Error("expected backtick detected in RUN")
	}
	if hasUnsafeShellExpansion("RUN echo hello") {
		t.Error("expected no expansion in simple RUN")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("short string should not be truncated")
	}
	got := truncate("this is a longer string", 10)
	if got != "this is a ..." {
		t.Errorf("unexpected truncation: %s", got)
	}
}

func TestAnalyzeDockerfileShellFormCmd(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nCMD nginx -g daemon off;",
		Cmd:     "nginx -g daemon off;",
		CmdExec: false,
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "shell_form_cmd" {
			found = true
		}
	}
	if !found {
		t.Error("expected shell_form_cmd finding")
	}
}

func TestAnalyzeDockerfileExecFormCmd(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: `FROM nginx\nCMD ["nginx", "-g", "daemon off;"]`,
		Cmd:     `["nginx", "-g", "daemon off;"]`,
		CmdExec: true,
	}
	dr := analyzeDockerfile(df)
	for _, f := range dr.Findings {
		if f.Rule == "shell_form_cmd" {
			t.Error("unexpected shell_form_cmd for exec form CMD")
		}
	}
}

func TestAnalyzeDockerfileShellFormEntrypoint(t *testing.T) {
	df := collect.Dockerfile{
		Path:           "Dockerfile",
		Content:        "FROM nginx\nENTRYPOINT /entrypoint.sh",
		Entrypoint:     "/entrypoint.sh",
		EntrypointExec: false,
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "shell_form_entrypoint" {
			found = true
		}
	}
	if !found {
		t.Error("expected shell_form_entrypoint finding")
	}
}

func TestAnalyzeDockerfilePipe(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM ubuntu\nRUN curl -s https://example.com | sh",
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "pipe_in_content" {
			found = true
		}
	}
	if !found {
		t.Error("expected pipe_in_content finding")
	}
}

func TestAnalyzeDockerfileUnsafeExpansion(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM ubuntu\nRUN echo $(whoami) > /tmp/user",
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "unsafe_shell_expand" {
			found = true
		}
	}
	if !found {
		t.Error("expected unsafe_shell_expand finding")
	}
}

func TestAnalyzeDockerfileClean(t *testing.T) {
	df := collect.Dockerfile{
		Path:           "Dockerfile",
		Content:        "FROM nginx\nRUN apt-get update\nCMD [\"nginx\"]",
		Cmd:            `["nginx"]`,
		CmdExec:        true,
		Entrypoint:     "",
		EntrypointExec: true,
	}
	dr := analyzeDockerfile(df)
	if len(dr.Findings) != 0 {
		t.Errorf("expected no findings for clean dockerfile, got %d", len(dr.Findings))
	}
}

func TestAnalyzeServiceShellCommand(t *testing.T) {
	svc := compose.Service{
		Name:    "web",
		Image:   "nginx",
		Command: []string{"sh", "-c", "echo $(whoami) && start"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "compose_shell_command" {
			found = true
		}
	}
	if !found {
		t.Error("expected compose_shell_command finding")
	}
}

func TestAnalyzeServiceSafeCommand(t *testing.T) {
	svc := compose.Service{
		Name:    "web",
		Image:   "nginx",
		Command: []string{"nginx", "-g", "daemon off"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	for _, f := range sr.Findings {
		if f.Rule == "compose_shell_command" {
			t.Error("unexpected compose_shell_command finding for safe command")
		}
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx", Command: []string{"sh", "-c", "echo test && start"}},
					{Name: "api", Image: "myapp"},
				},
			},
		},
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM python\nCMD python app.py",
				Cmd:     "python app.py",
				CmdExec: false,
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalDockerfiles != 1 {
		t.Errorf("expected 1 dockerfile, got %d", r.Summary.TotalDockerfiles)
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
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM python\nCMD python app.py",
				Cmd:     "python app.py",
				CmdExec: false,
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Exec Form") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(text, "Dockerfile") {
		t.Error("expected dockerfile in text output")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{Service: "a", Findings: []Finding{{Rule: "compose_shell_command"}}},
	}
	dockerfiles := []DockerfileResult{
		{File: "Dockerfile", Findings: []Finding{
			{Rule: "shell_form_cmd"},
			{Rule: "pipe_in_content"},
		}},
	}
	s := summarize(services, dockerfiles)
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.ComposeShellCmd != 1 {
		t.Errorf("expected 1 compose shell cmd, got %d", s.ComposeShellCmd)
	}
	if s.ShellFormCmd != 1 {
		t.Errorf("expected 1 shell form cmd, got %d", s.ShellFormCmd)
	}
}
