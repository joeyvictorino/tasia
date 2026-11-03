package traefikaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, envs, cmds []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: envs, Command: cmds, Ports: ports}
}

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{{Services: services}}}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "", Raw: ""}
}

func TestNoTraefikServices(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx", nil, nil, nil)))
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
}

func TestTraefikImageDetection(t *testing.T) {
	images := []string{"traefik:v2.10", "traefik/traefik:latest", "containous/traefik:1.7"}
	for _, img := range images {
		r := Analyze(collected(svc("proxy", img, nil, nil, nil)))
		if len(r.Services) != 1 {
			t.Errorf("image %q not detected as Traefik", img)
		}
	}
}

func TestDashboardExposed(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil, []string{"--api.dashboard=true"}, nil)))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_dashboard_exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected dashboard exposed finding")
	}
}

func TestInsecureAPI(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil, []string{"--api.insecure=true"}, nil)))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_insecure_api" {
			found = true
		}
	}
	if !found {
		t.Error("expected insecure API finding")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil,
		[]string{"--entrypoints.web.address=:80"}, nil)))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_no_tls" {
			found = true
		}
	}
	if !found {
		t.Error("expected no TLS finding")
	}
}

func TestTLSPresent(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil,
		[]string{"--entrypoints.web.address=:80", "--entrypoints.websecure.address=:443"}, nil)))
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_no_tls" {
			t.Error("should not flag no TLS when websecure entrypoint present")
		}
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil, nil, []compose.PortMapping{allIf(8080)})))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_exposed_port" {
			found = true
		}
	}
	if !found {
		t.Error("expected exposed port finding for 8080")
	}
}

func TestDebugEnabled(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil, []string{"--log.level=debug"}, nil)))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_debug_enabled" {
			found = true
		}
	}
	if !found {
		t.Error("expected debug enabled finding")
	}
}

func TestInsecureBackend(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil,
		[]string{"--serverstransport.insecureskipverify=true"}, nil)))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "traefik_insecure_backend" {
			found = true
		}
	}
	if !found {
		t.Error("expected insecure backend finding")
	}
}

func TestCleanTraefik(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil,
		[]string{"--entrypoints.websecure.address=:443"}, nil)))
	for _, svc := range r.Services {
		for _, f := range svc.Findings {
			if f.Level == "critical" {
				t.Errorf("clean config should not have critical findings: %s", f.Rule)
			}
		}
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx", nil, nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "No Traefik services found") {
		t.Error("expected empty message")
	}
}

func TestFormatTextHeader(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil, nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Traefik Security Audit") {
		t.Error("missing title")
	}
}

func TestSummaryCount(t *testing.T) {
	r := Analyze(collected(svc("proxy", "traefik:v2.10", nil,
		[]string{"--api.insecure=true", "--log.level=debug"}, nil)))
	if r.Summary.InsecureAPI != 1 {
		t.Errorf("expected 1 insecure API, got %d", r.Summary.InsecureAPI)
	}
	if r.Summary.DebugEnabled != 1 {
		t.Errorf("expected 1 debug, got %d", r.Summary.DebugEnabled)
	}
}
