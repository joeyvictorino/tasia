package rabbitmqaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "0.0.0.0"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func colPath(path string, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: path, ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsRabbitMQImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"rabbitmq:3.12", true},
		{"bitnami/rabbitmq:latest", true},
		{"rabbitmq:3-management", true},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		if got := isRabbitMQImage(tt.image); got != tt.want {
			t.Errorf("isRabbitMQImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3", nil, nil)))
	if r.Summary.DefaultCredentials == 0 {
		t.Error("expected rabbitmq_default_credentials finding when no credentials set")
	}
}

func TestGuestGuestCredentials(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3",
		[]string{"RABBITMQ_DEFAULT_USER=guest", "RABBITMQ_DEFAULT_PASS=guest"}, nil)))
	if r.Summary.DefaultCredentials == 0 {
		t.Error("expected rabbitmq_default_credentials finding for guest/guest")
	}
}

func TestWeakPassword(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3",
		[]string{"RABBITMQ_DEFAULT_USER=admin", "RABBITMQ_DEFAULT_PASS=password"}, nil)))
	if r.Summary.DefaultCredentials == 0 {
		t.Error("expected rabbitmq_default_credentials finding for weak password")
	}
}

func TestStrongCredentials(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3",
		[]string{"RABBITMQ_DEFAULT_USER=myuser", "RABBITMQ_DEFAULT_PASS=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultCredentials != 0 {
		t.Error("expected no rabbitmq_default_credentials finding with strong credentials")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected rabbitmq_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3",
		[]string{"RABBITMQ_SSL_CERTFILE=/certs/cert.pem", "RABBITMQ_DEFAULT_USER=admin", "RABBITMQ_DEFAULT_PASS=s3cur3!"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no rabbitmq_no_tls finding when TLS enabled")
	}
}

func TestManagementExposed(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3-management", nil, []compose.PortMapping{allIf(15672)})))
	if r.Summary.ManagementExposed == 0 {
		t.Error("expected rabbitmq_management_exposed finding")
	}
}

func TestManagementNotExposedWithCustomUser(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3",
		[]string{"RABBITMQ_DEFAULT_USER=admin", "RABBITMQ_DEFAULT_PASS=s3cur3!"},
		[]compose.PortMapping{allIf(15672)})))
	if r.Summary.ManagementExposed != 0 {
		t.Error("expected no management_exposed finding with custom user")
	}
}

func TestExposedAMQPPort(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3", nil, []compose.PortMapping{allIf(5672)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected rabbitmq_exposed_port finding for 5672")
	}
}

func TestExposedClusteringPort(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3", nil, []compose.PortMapping{allIf(25672)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected rabbitmq_exposed_port finding for 25672")
	}
}

func TestExposedSTOMPPort(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3", nil, []compose.PortMapping{allIf(61613)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected rabbitmq_exposed_port finding for 61613")
	}
}

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3", nil,
		[]compose.PortMapping{allIf(5672), allIf(15672), allIf(25672)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestGuestLoopbackDisabled(t *testing.T) {
	r := Analyze(col(svc("mq", "rabbitmq:3",
		[]string{"RABBITMQ_LOOPBACK_USERS=none", "RABBITMQ_DEFAULT_USER=admin", "RABBITMQ_DEFAULT_PASS=s3cur3!"},
		[]compose.PortMapping{allIf(5672)})))
	if r.Summary.GuestLoopback == 0 {
		t.Error("expected rabbitmq_guest_loopback finding")
	}
}

func TestNonRabbitMQSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("mq", "rabbitmq:3", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "RabbitMQ Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No RabbitMQ services found") {
		t.Error("expected empty message")
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("mq1", "rabbitmq:3", nil, nil),
		svc("mq2", "bitnami/rabbitmq", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
