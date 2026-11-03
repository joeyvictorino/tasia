package tlsconfig

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestWeakProtocolSSLv3(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"nginx", "ssl_protocols sslv3 tlsv1.2"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_weak_protocol") {
		t.Error("expected tls_weak_protocol for SSLv3")
	}
}

func TestWeakProtocolTLS10(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"TLS_MIN=min_protocol_version=tls1.0"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_weak_protocol") {
		t.Error("expected tls_weak_protocol for TLS 1.0")
	}
}

func TestNoWeakProtocol(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"ssl_protocols", "tlsv1.2", "tlsv1.3"},
	})
	r := Analyze(c)
	if findRule(r.Services, "tls_weak_protocol") {
		t.Error("should not flag TLS 1.2/1.3")
	}
}

func TestWeakCipherRC4(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"ssl_ciphers rc4-sha:aes128"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_weak_cipher") {
		t.Error("expected tls_weak_cipher for RC4")
	}
}

func TestWeakCipherNull(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"ssl_ciphers null-sha"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_weak_cipher") {
		t.Error("expected tls_weak_cipher for NULL cipher")
	}
}

func TestNoWeakCipher(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"ssl_ciphers", "ECDHE-RSA-AES256-GCM-SHA384"},
	})
	r := Analyze(c)
	if findRule(r.Services, "tls_weak_cipher") {
		t.Error("should not flag strong ciphers")
	}
}

func TestSelfSignedCert(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"CERT_MODE=generate_self_signed=true"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_self_signed") {
		t.Error("expected tls_self_signed")
	}
}

func TestSelfSignedFromLabel(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:   "web",
		Labels: map[string]string{"cert": "self-signed certificate"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_self_signed") {
		t.Error("expected tls_self_signed from label")
	}
}

func TestNoSelfSigned(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"nginx", "-g", "daemon off;"},
	})
	r := Analyze(c)
	if findRule(r.Services, "tls_self_signed") {
		t.Error("should not flag normal service")
	}
}

func TestNoVerify(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"SSL_OPTS=ssl_verify=false"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_no_verify") {
		t.Error("expected tls_no_verify")
	}
}

func TestSkipVerifyEnv(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=node_tls_reject_unauthorized=0"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_no_verify") {
		t.Error("expected tls_no_verify for NODE_TLS_REJECT_UNAUTHORIZED")
	}
}

func TestNoSkipVerify(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"SSL_VERIFY=true"},
	})
	r := Analyze(c)
	if findRule(r.Services, "tls_no_verify") {
		t.Error("should not flag when verify is enabled")
	}
}

func TestExpiredCert(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"CERT_CHECK=allow_expired=true"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_expired_cert") {
		t.Error("expected tls_expired_cert")
	}
}

func TestNoExpiredCert(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"nginx"},
	})
	r := Analyze(c)
	if findRule(r.Services, "tls_expired_cert") {
		t.Error("should not flag normal service")
	}
}

func TestInsecureRedirect(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"redirect http://example.com"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_insecure_redirect") {
		t.Error("expected tls_insecure_redirect")
	}
}

func TestInsecureRedirectHSTS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"HSTS=hsts=false"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_insecure_redirect") {
		t.Error("expected tls_insecure_redirect for disabled HSTS")
	}
}

func TestNoInsecureRedirect(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"redirect", "https://example.com"},
	})
	r := Analyze(c)
	if findRule(r.Services, "tls_insecure_redirect") {
		t.Error("should not flag HTTPS redirect")
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "insecure",
		Command:     []string{"ssl_protocols sslv3", "ssl_ciphers rc4-sha"},
		Environment: []string{"VERIFY=ssl_verify=false"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"ssl_protocols sslv3"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "TLS Configuration") {
		t.Error("expected 'TLS Configuration' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestEnvVarSource(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"TLS_PROTO=ssl_protocols sslv3"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "tls_weak_protocol") {
		t.Error("expected tls_weak_protocol from environment variable")
	}
}
