package bindmount

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name string, volumes []string) compose.Service {
	return compose.Service{Name: name, Volumes: volumes}
}

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestDockerSockDetection(t *testing.T) {
	c := collected(svc("agent", []string{"/var/run/docker.sock:/var/run/docker.sock"}))
	r := Analyze(c)
	if r.Summary.DockerSockMounts != 1 {
		t.Fatalf("expected 1 docker sock mount, got %d", r.Summary.DockerSockMounts)
	}
	if r.Services[0].Findings[0].Level != "critical" {
		t.Fatal("docker sock should be critical")
	}
}

func TestContainerdSockDetection(t *testing.T) {
	c := collected(svc("worker", []string{"/run/containerd/containerd.sock:/run/containerd/containerd.sock"}))
	r := Analyze(c)
	if r.Summary.DockerSockMounts != 1 {
		t.Fatalf("expected 1 sock mount, got %d", r.Summary.DockerSockMounts)
	}
}

func TestDangerousHostPathWritable(t *testing.T) {
	c := collected(svc("debug", []string{"/proc:/host-proc"}))
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "dangerous_host_path" && f.Level == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical dangerous_host_path for writable /proc mount")
	}
}

func TestDangerousHostPathReadOnly(t *testing.T) {
	c := collected(svc("monitor", []string{"/proc:/host-proc:ro"}))
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "dangerous_host_path" && f.Level == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected high dangerous_host_path for read-only /proc mount")
	}
}

func TestWritableHostBind(t *testing.T) {
	c := collected(svc("app", []string{"/data/app:/app"}))
	r := Analyze(c)
	if r.Summary.WritableBinds != 1 {
		t.Fatalf("expected 1 writable bind, got %d", r.Summary.WritableBinds)
	}
}

func TestReadOnlyHostBindSafe(t *testing.T) {
	c := collected(svc("app", []string{"/data/app:/app:ro"}))
	r := Analyze(c)
	if r.Summary.WritableBinds != 0 {
		t.Fatalf("expected 0 writable binds for ro mount, got %d", r.Summary.WritableBinds)
	}
}

func TestRecursiveBindMount(t *testing.T) {
	c := collected(svc("storage", []string{"/mnt/data:/data:rbind"}))
	r := Analyze(c)
	if r.Summary.RecursiveBinds != 1 {
		t.Fatalf("expected 1 recursive bind, got %d", r.Summary.RecursiveBinds)
	}
}

func TestNoFindings(t *testing.T) {
	c := collected(svc("safe", []string{}))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		svc("agent", []string{"/var/run/docker.sock:/var/run/docker.sock"}),
		svc("monitor", []string{"/proc:/proc:ro"}),
	)
	r := Analyze(c)
	if len(r.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(r.Services))
	}
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := collected(svc("app", []string{"/var/run/docker.sock:/var/run/docker.sock"}))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Bind Mount") {
		t.Fatal("expected header")
	}
	if !strings.Contains(text, "bind-mounts") || !strings.Contains(text, "critical") {
		t.Fatal("expected finding details")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := collected(svc("safe", []string{}))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := collected(svc("app", []string{"/proc:/proc"}))
	r := Analyze(c)
	out := FormatJSON(r)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := data["services"]; !ok {
		t.Fatal("expected services key")
	}
}

func TestSummaryHostPathCount(t *testing.T) {
	c := collected(svc("app", []string{
		"/var/run/docker.sock:/var/run/docker.sock",
		"/data:/data",
	}))
	r := Analyze(c)
	if r.Summary.HostPathMounts < 2 {
		t.Fatalf("expected >= 2 host path mounts, got %d", r.Summary.HostPathMounts)
	}
}
