package minioaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func svcCmd(name, image string, env []string, ports []compose.PortMapping, cmd []string) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports, Command: cmd}
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

func TestIsMinioImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"minio/minio:latest", true},
		{"bitnami/minio:2023", true},
		{"quay.io/minio/minio:RELEASE", true},
		{"minio/mc:latest", true},
		{"nginx:latest", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isMinioImage(tt.image); got != tt.want {
			t.Errorf("isMinioImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{"MINIO_ROOT_USER=minioadmin", "MINIO_ROOT_PASSWORD=minioadmin"}, nil)))
	if r.Summary.DefaultCredentials == 0 {
		t.Error("expected minio_default_credentials finding")
	}
}

func TestDefaultAccessKey(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{"MINIO_ACCESS_KEY=minio"}, nil)))
	if r.Summary.DefaultCredentials == 0 {
		t.Error("expected minio_default_credentials finding for legacy access key")
	}
}

func TestDefaultSecretKey(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{"MINIO_SECRET_KEY=password"}, nil)))
	if r.Summary.DefaultCredentials == 0 {
		t.Error("expected minio_default_credentials finding for legacy secret key")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected minio_no_tls finding")
	}
}

func TestTLSViaCertsDir(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{"MINIO_CERTS_DIR=/certs"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS when MINIO_CERTS_DIR is set")
	}
}

func TestTLSViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("s3", "minio/minio", nil, nil, []string{"server", "--certs-dir", "/certs"})))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS when --certs-dir is in command")
	}
}

func TestExposedAPIPort(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", nil, []compose.PortMapping{allIf(9000)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected minio_exposed_port finding for port 9000")
	}
}

func TestExposedConsolePort(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", nil, []compose.PortMapping{allIf(9001)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected minio_exposed_port finding for port 9001")
	}
}

func TestBothPortsExposed(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", nil, []compose.PortMapping{allIf(9000), allIf(9001)})))
	if r.Summary.ExposedPort != 2 {
		t.Errorf("expected 2 exposed port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestRootCredentials(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{"MINIO_ROOT_USER=root"}, nil)))
	if r.Summary.RootCredentials == 0 {
		t.Error("expected minio_root_credentials finding")
	}
}

func TestBrowserExposed(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", nil, []compose.PortMapping{allIf(9001)})))
	if r.Summary.BrowserExposed == 0 {
		t.Error("expected minio_browser_exposed finding")
	}
}

func TestBrowserDisabled(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{"MINIO_BROWSER=OFF"}, []compose.PortMapping{allIf(9001)})))
	if r.Summary.BrowserExposed != 0 {
		t.Error("should not flag browser when MINIO_BROWSER=OFF")
	}
}

func TestNonMinioSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("s3", "minio/minio", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "MinIO Security Audit") {
		t.Error("missing title")
	}
	if !strings.Contains(text, "/test") {
		t.Error("missing path")
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
		svc("s3a", "minio/minio", nil, nil),
		svc("s3b", "bitnami/minio", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}

func TestStrongCredentials(t *testing.T) {
	r := Analyze(col(svc("s3", "minio/minio", []string{
		"MINIO_ROOT_USER=myCustomUser",
		"MINIO_ROOT_PASSWORD=V3ryStr0ngP@ssw0rd!",
		"MINIO_CERTS_DIR=/certs",
	}, nil)))
	if r.Summary.DefaultCredentials != 0 {
		t.Error("should not flag strong credentials")
	}
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS with certs configured")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No MinIO services found") {
		t.Error("missing empty message")
	}
}
