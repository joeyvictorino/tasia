package socketaudit

import (
	"encoding/json"
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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestDockerSocketMounted(t *testing.T) {
	c := collected(compose.Service{
		Name:    "proxy",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_docker_mounted") {
		t.Error("expected socket_docker_mounted finding")
	}
}

func TestDockerSocketReadonly(t *testing.T) {
	c := collected(compose.Service{
		Name:    "proxy",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_docker_mounted") {
		t.Error("expected socket_docker_mounted even with ro")
	}
	if hasRule(r.Services[0], "socket_docker_readonly") {
		t.Error("should not flag readonly when :ro is set")
	}
}

func TestDockerSocketReadWrite(t *testing.T) {
	c := collected(compose.Service{
		Name:    "proxy",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_docker_readonly") {
		t.Error("expected socket_docker_readonly for read-write docker socket")
	}
}

func TestContainerdSocket(t *testing.T) {
	c := collected(compose.Service{
		Name:    "runtime",
		Volumes: []string{"/var/run/containerd/containerd.sock:/var/run/containerd/containerd.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_containerd_mounted") {
		t.Error("expected socket_containerd_mounted finding")
	}
}

func TestUnknownSocket(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/var/run/custom.sock:/var/run/custom.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_unknown_exposed") {
		t.Error("expected socket_unknown_exposed for unknown socket")
	}
}

func TestSocketWorldWritable(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/var/run/custom.sock:/var/run/custom.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_world_writable") {
		t.Error("expected socket_world_writable for read-write socket")
	}
}

func TestSocketReadonlyNotWorldWritable(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/var/run/custom.sock:/var/run/custom.sock:ro"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "socket_world_writable") {
		t.Error("should not flag world_writable when :ro is set")
	}
}

func TestMultipleSockets(t *testing.T) {
	c := collected(compose.Service{
		Name: "multi",
		Volumes: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
			"/var/run/custom.sock:/var/run/custom.sock",
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_multiple_exposed") {
		t.Error("expected socket_multiple_exposed for 2 sockets")
	}
}

func TestNoSockets(t *testing.T) {
	c := collected(compose.Service{
		Name:    "web",
		Volumes: []string{"/data:/data"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for no socket mounts, got %d", len(r.Services[0].Findings))
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "proxy", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}},
		compose.Service{Name: "web"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithSocketMounts != 1 {
		t.Errorf("expected 1 with socket mounts, got %d", r.Summary.WithSocketMounts)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:    "proxy",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "Socket Exposure Audit") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:    "proxy",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestRunDockerSocket(t *testing.T) {
	c := collected(compose.Service{
		Name:    "proxy",
		Volumes: []string{"/run/docker.sock:/run/docker.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "socket_docker_mounted") {
		t.Error("expected socket_docker_mounted for /run/docker.sock")
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
