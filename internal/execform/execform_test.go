package execform

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestIsShellForm(t *testing.T) {
	if !isShellForm("python app.py") {
		t.Error("expected shell form for plain command")
	}
	if isShellForm("[\"python\", \"app.py\"]") {
		t.Error("expected exec form for JSON array")
	}
	if isShellForm("") {
		t.Error("expected false for empty string")
	}
}

func TestAnalyzeServiceShellEntrypoint(t *testing.T) {
	svc := compose.Service{
		Name:       "web",
		Image:      "nginx",
		Entrypoint: []string{"python app.py"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "shell_form_entrypoint" {
			found = true
		}
	}
	if !found {
		t.Error("expected shell_form_entrypoint finding")
	}
}

func TestAnalyzeServiceShellCommand(t *testing.T) {
	svc := compose.Service{
		Name:    "web",
		Image:   "nginx",
		Command: []string{"python app.py"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "shell_form_command" {
			found = true
		}
	}
	if !found {
		t.Error("expected shell_form_command finding")
	}
}

func TestAnalyzeServiceExecForm(t *testing.T) {
	svc := compose.Service{
		Name:       "web",
		Image:      "nginx",
		Entrypoint: []string{"python", "app.py"},
		Command:    []string{"--host", "0.0.0.0"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings for exec form, got %d", len(sr.Findings))
	}
}

func TestAnalyzeServiceNoEntrypoint(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx"}
	sr := analyzeService(svc, "docker-compose.yml")
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings for service without entrypoint/command, got %d", len(sr.Findings))
	}
}

func TestAnalyzeDockerfileShellEntrypoint(t *testing.T) {
	df := collect.Dockerfile{
		Path:           "Dockerfile",
		Content:        "FROM python\nENTRYPOINT python app.py",
		Entrypoint:     "python app.py",
		EntrypointExec: false,
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "dockerfile_shell_entrypoint" {
			found = true
		}
	}
	if !found {
		t.Error("expected dockerfile_shell_entrypoint finding")
	}
}

func TestAnalyzeDockerfileShellCmd(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM python\nCMD python app.py",
		Cmd:     "python app.py",
		CmdExec: false,
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "dockerfile_shell_cmd" {
			found = true
		}
	}
	if !found {
		t.Error("expected dockerfile_shell_cmd finding")
	}
}

func TestAnalyzeDockerfileExecEntrypoint(t *testing.T) {
	df := collect.Dockerfile{
		Path:           "Dockerfile",
		Content:        "FROM python\nENTRYPOINT [\"python\", \"app.py\"]",
		Entrypoint:     "[\"python\", \"app.py\"]",
		EntrypointExec: true,
	}
	dr := analyzeDockerfile(df)
	if len(dr.Findings) != 0 {
		t.Errorf("expected no findings for exec form, got %d", len(dr.Findings))
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx", Entrypoint: []string{"python app.py"}},
					{Name: "api", Image: "myapp"},
				},
			},
		},
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM python\nCMD python app.py", Cmd: "python app.py", CmdExec: false},
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
				Services: []compose.Service{{Name: "svc1", Image: "nginx", Entrypoint: []string{"bash run.sh"}}},
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Exec Form") {
		t.Error("expected header in text output")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{Service: "a", Findings: []Finding{
			{Rule: "shell_form_entrypoint"},
			{Rule: "shell_form_command"},
		}},
	}
	dockerfiles := []DockerfileResult{
		{File: "Dockerfile", Findings: []Finding{{Rule: "dockerfile_shell_entrypoint"}}},
	}
	s := summarize(services, dockerfiles)
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.ShellForm != 3 {
		t.Errorf("expected 3 shell_form, got %d", s.ShellForm)
	}
	if s.NoSignalHandling != 2 {
		t.Errorf("expected 2 no_signal_handling, got %d", s.NoSignalHandling)
	}
}
