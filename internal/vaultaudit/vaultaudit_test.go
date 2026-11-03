package vaultaudit

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

func TestIsVaultImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"vault:1.15", true},
		{"hashicorp/vault:latest", true},
		{"Vault:1.14", true},
		{"nginx:latest", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isVaultImage(tt.image); got != tt.want {
			t.Errorf("isVaultImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestDevModeViaEnv(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", []string{"VAULT_DEV_ROOT_TOKEN_ID=myroot"}, nil)))
	if r.Summary.DevMode == 0 {
		t.Error("expected vault_dev_mode finding via env")
	}
}

func TestDevModeViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("secrets", "vault:1.15", nil, nil, []string{"server", "-dev"})))
	if r.Summary.DevMode == 0 {
		t.Error("expected vault_dev_mode finding via command")
	}
}

func TestDevModeDoubleHyphen(t *testing.T) {
	r := Analyze(col(svcCmd("secrets", "vault:1.15", nil, nil, []string{"server", "--dev"})))
	if r.Summary.DevMode == 0 {
		t.Error("expected vault_dev_mode finding via --dev")
	}
}

func TestNoDevMode(t *testing.T) {
	r := Analyze(col(svcCmd("secrets", "vault:1.15", nil, nil, []string{"server", "-config=/vault/config"})))
	if r.Summary.DevMode != 0 {
		t.Error("should not flag dev mode for production config")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected vault_no_tls finding")
	}
}

func TestTLSViaAddr(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", []string{"VAULT_ADDR=https://vault:8200"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS when VAULT_ADDR uses https")
	}
}

func TestTLSViaCert(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", []string{"VAULT_TLS_CERT_FILE=/certs/cert.pem"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS when cert file is set")
	}
}

func TestExposedAPIPort(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", nil, []compose.PortMapping{allIf(8200)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected vault_exposed_port finding for 8200")
	}
}

func TestExposedClusterPort(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", nil, []compose.PortMapping{allIf(8201)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected vault_exposed_port finding for 8201")
	}
}

func TestBothPortsExposed(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", nil, []compose.PortMapping{allIf(8200), allIf(8201)})))
	if r.Summary.ExposedPort != 2 {
		t.Errorf("expected 2 exposed port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestRootTokenInEnv(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", []string{"VAULT_TOKEN=s.abcdef123456"}, nil)))
	if r.Summary.RootTokenInEnv == 0 {
		t.Error("expected vault_root_token_in_env finding")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", []string{"VAULT_DEV_ROOT_TOKEN_ID=root"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected vault_default_password finding")
	}
}

func TestDefaultTokenPassword(t *testing.T) {
	r := Analyze(col(svc("secrets", "vault:1.15", []string{"VAULT_TOKEN=admin"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected vault_default_password finding for weak VAULT_TOKEN")
	}
}

func TestNonVaultSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("secrets", "vault:1.15", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Vault Security Audit") {
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
		svc("v1", "vault:1.15", nil, nil),
		svc("v2", "hashicorp/vault:latest", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}

func TestSecureVault(t *testing.T) {
	r := Analyze(col(svcCmd("secrets", "vault:1.15", []string{
		"VAULT_ADDR=https://vault:8200",
		"VAULT_TLS_CERT_FILE=/certs/cert.pem",
	}, nil, []string{"server", "-config=/vault/config"})))
	if r.Summary.DevMode != 0 {
		t.Error("should not flag dev mode")
	}
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Vault services found") {
		t.Error("missing empty message")
	}
}
