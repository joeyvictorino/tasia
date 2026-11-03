package grafanaaudit

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

func svc(name, image string, envs []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: envs, Ports: ports}
}

func TestIsGrafanaImage(t *testing.T) {
	if !isGrafanaImage("grafana/grafana:10.0") {
		t.Error("should detect grafana/grafana")
	}
	if isGrafanaImage("postgres:15") {
		t.Error("should not detect postgres")
	}
}

func TestDefaultCredentials(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_SECURITY_ADMIN_PASSWORD=admin"}, nil))
	r := Analyze(c)
	if r.Summary.DefaultCredentials != 1 {
		t.Errorf("expected 1 default_credentials, got %d", r.Summary.DefaultCredentials)
	}
}

func TestAnonAccess(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_AUTH_ANONYMOUS_ENABLED=true"}, nil))
	r := Analyze(c)
	if r.Summary.AnonAccess != 1 {
		t.Errorf("expected 1 anon_access, got %d", r.Summary.AnonAccess)
	}
}

func TestDisabledAuth(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_AUTH_DISABLE_LOGIN_FORM=true"}, nil))
	r := Analyze(c)
	if r.Summary.DisabledAuth != 1 {
		t.Errorf("expected 1 disabled_auth, got %d", r.Summary.DisabledAuth)
	}
}

func TestExposedPort(t *testing.T) {
	ports := []compose.PortMapping{{HostPort: 3000, TargetPort: 3000, Raw: "3000:3000"}}
	c := coll(svc("grafana", "grafana/grafana", nil, ports))
	r := Analyze(c)
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected 1 exposed_port, got %d", r.Summary.ExposedPort)
	}
}

func TestDebugEnabled(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_LOG_LEVEL=debug"}, nil))
	r := Analyze(c)
	if r.Summary.DebugEnabled != 1 {
		t.Errorf("expected 1 debug_enabled, got %d", r.Summary.DebugEnabled)
	}
}

func TestAlertingExposed(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_UNIFIED_ALERTING_ENABLED=true"}, nil))
	r := Analyze(c)
	if r.Summary.AlertingExposed != 1 {
		t.Errorf("expected 1 alerting_exposed, got %d", r.Summary.AlertingExposed)
	}
}

func TestNoGrafanaServices(t *testing.T) {
	c := coll(svc("postgres", "postgres:15", nil, nil))
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
}

func TestCleanService(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_SECURITY_ADMIN_PASSWORD=SuperStr0ng!Pass"}, nil))
	r := Analyze(c)
	if r.Summary.DefaultCredentials != 0 {
		t.Error("strong password should not trigger default credentials")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := coll(svc("postgres", "postgres:15", nil, nil))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "No Grafana services") {
		t.Error("missing empty message")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_SECURITY_ADMIN_PASSWORD=admin"}, nil))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "grafana_default_credentials") {
		t.Error("missing finding in text")
	}
}

func TestMultipleImages(t *testing.T) {
	if !isGrafanaImage("bitnami/grafana:latest") {
		t.Error("should detect bitnami/grafana")
	}
	if !isGrafanaImage("grafana/grafana-enterprise:10") {
		t.Error("should detect enterprise")
	}
}

func TestBasicAuthDisabled(t *testing.T) {
	c := coll(svc("grafana", "grafana/grafana", []string{"GF_AUTH_BASIC_ENABLED=false"}, nil))
	r := Analyze(c)
	if r.Summary.DisabledAuth != 1 {
		t.Errorf("expected disabled_auth, got %d", r.Summary.DisabledAuth)
	}
}
