package certexpiry

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestCleanService(t *testing.T) {
	svc := compose.Service{Name: "safe"}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSelfSignedCert(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"GENERATE_SELF_SIGNED=true"}}
	r := Analyze(collected(svc))
	if r.Summary.SelfSignedCerts != 1 {
		t.Errorf("expected 1 self-signed cert, got %d", r.Summary.SelfSignedCerts)
	}
}

func TestSelfSignedVariant(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"SELF_SIGNED=1"}}
	r := Analyze(collected(svc))
	if r.Summary.SelfSignedCerts != 1 {
		t.Errorf("expected 1, got %d", r.Summary.SelfSignedCerts)
	}
}

func TestTLSValidationDisabledNode(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}}
	r := Analyze(collected(svc))
	if r.Summary.TLSDisabled != 1 {
		t.Errorf("expected 1, got %d", r.Summary.TLSDisabled)
	}
}

func TestTLSValidationDisabledPython(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"PYTHONHTTPSVERIFY=0"}}
	r := Analyze(collected(svc))
	if r.Summary.TLSDisabled != 1 {
		t.Errorf("expected 1, got %d", r.Summary.TLSDisabled)
	}
}

func TestTLSValidationDisabledGit(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"GIT_SSL_NO_VERIFY=true"}}
	r := Analyze(collected(svc))
	if r.Summary.TLSDisabled != 1 {
		t.Errorf("expected 1, got %d", r.Summary.TLSDisabled)
	}
}

func TestWeakTLSVersion(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"TLS_MIN_VERSION=1.0"}}
	r := Analyze(collected(svc))
	if r.Summary.WeakTLSVersion != 1 {
		t.Errorf("expected 1, got %d", r.Summary.WeakTLSVersion)
	}
}

func TestWeakTLSVersion11(t *testing.T) {
	svc := compose.Service{Name: "app", Environment: []string{"TLS_MIN_VERSION=1.1"}}
	r := Analyze(collected(svc))
	if r.Summary.WeakTLSVersion != 1 {
		t.Errorf("expected 1, got %d", r.Summary.WeakTLSVersion)
	}
}

func TestCertMountWritable(t *testing.T) {
	svc := compose.Service{Name: "app", Volumes: []string{"/etc/ssl/certs:/certs"}}
	r := Analyze(collected(svc))
	if r.Summary.CertMountNoRotate != 1 {
		t.Errorf("expected 1, got %d", r.Summary.CertMountNoRotate)
	}
}

func TestCertMountReadOnly(t *testing.T) {
	svc := compose.Service{Name: "app", Volumes: []string{"/etc/ssl/certs:/certs:ro"}}
	r := Analyze(collected(svc))
	if r.Summary.CertMountNoRotate != 0 {
		t.Errorf("expected 0, got %d", r.Summary.CertMountNoRotate)
	}
	if r.Summary.CertPathExposed != 1 {
		t.Errorf("expected 1 cert path exposed, got %d", r.Summary.CertPathExposed)
	}
}

func TestLetsencryptMount(t *testing.T) {
	svc := compose.Service{Name: "app", Volumes: []string{"/etc/letsencrypt/live:/certs"}}
	r := Analyze(collected(svc))
	if r.Summary.CertPathExposed != 1 {
		t.Errorf("expected 1, got %d", r.Summary.CertPathExposed)
	}
}

func TestInsecureFlag(t *testing.T) {
	svc := compose.Service{Name: "app", Command: []string{"curl", "--insecure", "https://api"}}
	r := Analyze(collected(svc))
	if r.Summary.NoCertValidation != 1 {
		t.Errorf("expected 1, got %d", r.Summary.NoCertValidation)
	}
}

func TestNoCheckCertificate(t *testing.T) {
	svc := compose.Service{Name: "app", Entrypoint: []string{"wget", "--no-check-certificate", "https://x"}}
	r := Analyze(collected(svc))
	if r.Summary.NoCertValidation != 1 {
		t.Errorf("expected 1, got %d", r.Summary.NoCertValidation)
	}
}

func TestMultipleIssues(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0", "GENERATE_SELF_SIGNED=true"},
		Volumes:     []string{"/etc/ssl/private:/ssl"},
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0, got %d", r.Summary.TotalFindings)
	}
}

func TestSafeEnvVars(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"TLS_MIN_VERSION=1.3", "APP_PORT=443"},
	}
	r := Analyze(collected(svc))
	if r.Summary.WeakTLSVersion != 0 {
		t.Errorf("expected 0 weak TLS, got %d", r.Summary.WeakTLSVersion)
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{Name: "a", Environment: []string{"SELF_SIGNED=true"}}
	svc2 := compose.Service{Name: "b", Environment: []string{"GIT_SSL_NO_VERIFY=1"}}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SelfSignedCerts != 1 || r.Summary.TLSDisabled != 1 {
		t.Errorf("expected 1 self-signed and 1 TLS disabled")
	}
}
