package layeraudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(collect.Collected{})
	if r.Total != 0 {
		t.Errorf("total = %d", r.Total)
	}
}

func TestExcessiveRun(t *testing.T) {
	var lines []string
	for i := 0; i < 12; i++ {
		lines = append(lines, "RUN echo step"+string(rune('a'+i)))
	}
	df := collect.Dockerfile{Path: "Dockerfile", Content: strings.Join(lines, "\n")}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	found := false
	for _, f := range r.Files[0].Findings {
		if f.Rule == "excessive_run" {
			found = true
		}
	}
	if !found {
		t.Error("expected excessive_run finding")
	}
}

func TestConsecutiveRun(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y git
RUN apt-get install -y vim
CMD ["/bin/bash"]`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	found := false
	for _, f := range r.Files[0].Findings {
		if f.Rule == "consecutive_run" {
			found = true
		}
	}
	if !found {
		t.Error("expected consecutive_run finding")
	}
}

func TestAptNoCleanup(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	found := false
	for _, f := range r.Files[0].Findings {
		if f.Rule == "apt_no_cleanup" {
			found = true
		}
	}
	if !found {
		t.Error("expected apt_no_cleanup finding")
	}
}

func TestAptWithCleanup(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	for _, f := range r.Files[0].Findings {
		if f.Rule == "apt_no_cleanup" {
			t.Error("should not flag apt with cleanup")
		}
	}
}

func TestAddURL(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM alpine\nADD https://example.com/app.tar.gz /opt/",
		Adds: []collect.DockerfileAdd{
			{Source: "https://example.com/app.tar.gz", Dest: "/opt/", Line: 2, IsURL: true},
		},
	}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	found := false
	for _, f := range r.Files[0].Findings {
		if f.Rule == "add_url" {
			found = true
		}
	}
	if !found {
		t.Error("expected add_url finding")
	}
}

func TestCurlPipeShell(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/install.sh | bash`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	found := false
	for _, f := range r.Files[0].Findings {
		if f.Rule == "curl_pipe_shell" {
			found = true
		}
	}
	if !found {
		t.Error("expected curl_pipe_shell finding")
	}
}

func TestPipNoCache(t *testing.T) {
	content := `FROM python:3.11
RUN pip install requests`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	found := false
	for _, f := range r.Files[0].Findings {
		if f.Rule == "pip_no_cache_dir" {
			found = true
		}
	}
	if !found {
		t.Error("expected pip_no_cache_dir finding")
	}
}

func TestLayerCount(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN echo 1
COPY . /app
ADD data.tar /opt/
RUN echo 2`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	if r.Files[0].LayerCount != 4 {
		t.Errorf("layer_count = %d, want 4", r.Files[0].LayerCount)
	}
	if r.Files[0].RunCount != 2 {
		t.Errorf("run_count = %d, want 2", r.Files[0].RunCount)
	}
}

func TestFormatText(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl`
	df := collect.Dockerfile{Path: "Dockerfile", Content: content}
	r := Analyze(collect.Collected{Dockerfiles: []collect.Dockerfile{df}})
	text := FormatText(r)
	if !strings.Contains(text, "Layer Audit") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "Dockerfile") {
		t.Error("missing file name")
	}
}
