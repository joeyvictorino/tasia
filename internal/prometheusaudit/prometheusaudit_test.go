package prometheusaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func coll(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{{Services: svcs}},
	}
}

func svc(name, image string, envs []string, ports []compose.PortMapping, cmds []string) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: envs, Ports: ports, Command: cmds}
}

func TestIsPrometheusImage(t *testing.T) {
	if !isPrometheusImage("prom/prometheus:v2.45") {
		t.Error("should detect prom/prometheus")
	}
	if isPrometheusImage("postgres:15") {
		t.Error("should not detect postgres")
	}
}

func TestAdminAPI(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", nil, nil, []string{"--web.enable-admin-api"}))
	r := Analyze(c)
	if r.Summary.AdminEnabled != 1 {
		t.Errorf("expected 1 admin, got %d", r.Summary.AdminEnabled)
	}
}

func TestLifecycleAPI(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", nil, nil, []string{"--web.enable-lifecycle"}))
	r := Analyze(c)
	if r.Summary.LifecycleAPI != 1 {
		t.Errorf("expected 1 lifecycle, got %d", r.Summary.LifecycleAPI)
	}
}

func TestExposedPort(t *testing.T) {
	ports := []compose.PortMapping{{HostPort: 9090, TargetPort: 9090, Raw: "9090:9090"}}
	c := coll(svc("prom", "prom/prometheus", nil, ports, nil))
	r := Analyze(c)
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected 1 exposed, got %d", r.Summary.ExposedPort)
	}
}

func TestRemoteWrite(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", nil, nil, []string{"--web.enable-remote-write-receiver"}))
	r := Analyze(c)
	if r.Summary.RemoteWrite != 1 {
		t.Errorf("expected 1 remote_write, got %d", r.Summary.RemoteWrite)
	}
}

func TestDebugEnabled(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", nil, nil, []string{"--log.level=debug"}))
	r := Analyze(c)
	if r.Summary.DebugEnabled != 1 {
		t.Errorf("expected 1 debug, got %d", r.Summary.DebugEnabled)
	}
}

func TestNoPrometheusServices(t *testing.T) {
	c := coll(svc("postgres", "postgres:15", nil, nil, nil))
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
}

func TestCleanService(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", nil, nil, nil))
	r := Analyze(c)
	found := false
	for _, s := range r.Services {
		if len(s.Findings) > 0 {
			found = true
		}
	}
	if found {
		t.Error("clean prometheus should have no findings")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := coll(svc("postgres", "postgres:15", nil, nil, nil))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "No Prometheus services") {
		t.Error("missing empty message")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", nil, nil, []string{"--web.enable-admin-api"}))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "prometheus_admin_api") {
		t.Error("missing finding in text")
	}
}

func TestMultipleImages(t *testing.T) {
	if !isPrometheusImage("bitnami/prometheus:latest") {
		t.Error("should detect bitnami/prometheus")
	}
	if !isPrometheusImage("quay.io/prometheus/prometheus:v2") {
		t.Error("should detect quay.io prometheus")
	}
}

func TestRemoteWriteEnv(t *testing.T) {
	c := coll(svc("prom", "prom/prometheus", []string{"REMOTE_WRITE=enabled"}, nil, nil))
	r := Analyze(c)
	if r.Summary.RemoteWrite != 1 {
		t.Errorf("expected 1 remote_write from env, got %d", r.Summary.RemoteWrite)
	}
}
