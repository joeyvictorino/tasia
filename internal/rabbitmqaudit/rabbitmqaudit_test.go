package rabbitmqaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func coll(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{{Services: services}},
	}
}

func TestIsRabbitmqImage(t *testing.T) {
	tests := []struct{ img string; want bool }{
		{"rabbitmq:3-management", true},
		{"bitnami/rabbitmq:latest", true},
		{"nginx:latest", false},
		{"RABBITMQ:3", true},
	}
	for _, tc := range tests {
		if got := isRabbitmqImage(tc.img); got != tc.want {
			t.Errorf("isRabbitmqImage(%q) = %v, want %v", tc.img, got, tc.want)
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	envs := []string{"RABBITMQ_DEFAULT_PASS=guest"}
	if !hasDefaultCredentials(envs) {
		t.Error("expected default credentials detected")
	}
}

func TestNoDefaultCredentials(t *testing.T) {
	envs := []string{"RABBITMQ_DEFAULT_PASS=str0ngP@ss!"}
	if hasDefaultCredentials(envs) {
		t.Error("strong password should not trigger")
	}
}

func TestGuestAccess(t *testing.T) {
	envs := []string{"RABBITMQ_DEFAULT_USER=guest"}
	if !hasGuestAccess(envs) {
		t.Error("expected guest access detected")
	}
}

func TestNoTLS(t *testing.T) {
	envs := []string{"RABBITMQ_SSL=false"}
	if !hasNoTLS(envs) {
		t.Error("expected no TLS detected")
	}
}

func TestDebugEnabled(t *testing.T) {
	envs := []string{"RABBITMQ_LOG=debug"}
	if !hasDebugEnabled(envs) {
		t.Error("expected debug detected")
	}
}

func TestNoAuthBackend(t *testing.T) {
	envs := []string{"AUTH_BACKENDS=none"}
	if !hasNoAuthBackend(envs) {
		t.Error("expected no auth backend detected")
	}
}

func TestExposedManagementPort(t *testing.T) {
	svc := compose.Service{
		Name:  "rmq",
		Image: "rabbitmq:3-management",
		Ports: []compose.PortMapping{{HostPort: 15672, TargetPort: 15672, HostIP: ""}},
	}
	sr := analyzeService(svc)
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "rabbitmq_management_exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected management exposed finding")
	}
}

func TestExposedAMQPPort(t *testing.T) {
	svc := compose.Service{
		Name:  "rmq",
		Image: "rabbitmq",
		Ports: []compose.PortMapping{{HostPort: 5672, TargetPort: 5672, HostIP: ""}},
	}
	sr := analyzeService(svc)
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "rabbitmq_exposed_port" {
			found = true
		}
	}
	if !found {
		t.Error("expected exposed port finding")
	}
}

func TestBoundPort(t *testing.T) {
	svc := compose.Service{
		Name:  "rmq",
		Image: "rabbitmq",
		Ports: []compose.PortMapping{{HostPort: 5672, TargetPort: 5672, HostIP: "127.0.0.1"}},
	}
	sr := analyzeService(svc)
	for _, f := range sr.Findings {
		if f.Rule == "rabbitmq_exposed_port" {
			t.Error("localhost-bound port should not trigger")
		}
	}
}

func TestCleanService(t *testing.T) {
	svc := compose.Service{
		Name:  "rmq",
		Image: "rabbitmq",
	}
	sr := analyzeService(svc)
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(sr.Findings))
	}
}

func TestAnalyzeSkipsNonRabbitmq(t *testing.T) {
	c := coll(compose.Service{Name: "web", Image: "nginx"})
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("should skip non-rabbitmq services")
	}
}

func TestAnalyzeSummary(t *testing.T) {
	c := coll(compose.Service{
		Name:        "rmq",
		Image:       "rabbitmq",
		Environment: []string{"RABBITMQ_DEFAULT_PASS=guest", "RABBITMQ_DEFAULT_USER=guest"},
	})
	r := Analyze(c)
	if r.Summary.DefaultCredentials < 1 {
		t.Error("expected default credentials in summary")
	}
	if r.Summary.GuestAccess < 1 {
		t.Error("expected guest access in summary")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Report{Path: "/test"}
	text := FormatText(r)
	if !strings.Contains(text, "No RabbitMQ") {
		t.Error("should say no RabbitMQ services")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	c := coll(compose.Service{
		Name:        "rmq",
		Image:       "rabbitmq",
		Environment: []string{"RABBITMQ_DEFAULT_PASS=guest"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "rabbitmq_default_credentials") {
		t.Error("format should include finding rule")
	}
}
