package certpin

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services []compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestEmptyServices(t *testing.T) {
	r := Analyze(collected(nil))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestTLSVerifyDisabled(t *testing.T) {
	svcs := []compose.Service{
		{Name: "api", Image: "myapi:latest", Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TLSVerifyDisabled == 0 {
		t.Fatal("expected TLS verify disabled finding")
	}
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "certpin_tls_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected certpin_tls_disabled rule")
	}
}

func TestSSLVerifyFalse(t *testing.T) {
	svcs := []compose.Service{
		{Name: "worker", Image: "python:3.11", Environment: []string{"SSL_VERIFY=false"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TLSVerifyDisabled == 0 {
		t.Fatal("expected TLS verify disabled finding for SSL_VERIFY=false")
	}
}

func TestPythonHTTPSVerify(t *testing.T) {
	svcs := []compose.Service{
		{Name: "worker", Image: "python:3.11", Environment: []string{"PYTHONHTTPSVERIFY=0"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TLSVerifyDisabled == 0 {
		t.Fatal("expected TLS verify disabled finding for PYTHONHTTPSVERIFY=0")
	}
}

func TestSelfSignedAllowed(t *testing.T) {
	svcs := []compose.Service{
		{Name: "api", Image: "myapi:latest", Environment: []string{"SELF_SIGNED=true"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.SelfSignedAllowed == 0 {
		t.Fatal("expected self-signed finding")
	}
}

func TestTLSInsecure(t *testing.T) {
	svcs := []compose.Service{
		{Name: "api", Image: "myapi:latest", Environment: []string{"TLS_INSECURE=true"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.SelfSignedAllowed == 0 {
		t.Fatal("expected self-signed finding for TLS_INSECURE=true")
	}
}

func TestMissingCertPinSensitive(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.MissingCertPin == 0 {
		t.Fatal("expected missing cert pin for sensitive service")
	}
}

func TestHasCertPinning(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15", Environment: []string{"SSL_CA_CERTS=/certs/ca.pem"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.MissingCertPin != 0 {
		t.Fatal("should not flag missing cert pin when CA cert is configured")
	}
}

func TestInsecureProtocol(t *testing.T) {
	svcs := []compose.Service{
		{Name: "redis", Image: "redis:7", Environment: []string{"REDIS_URL=http://redis:6379"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.InsecureProtocol == 0 {
		t.Fatal("expected insecure protocol finding for HTTP on sensitive service")
	}
}

func TestSecureProtocolNoFinding(t *testing.T) {
	svcs := []compose.Service{
		{Name: "redis", Image: "redis:7", Environment: []string{"REDIS_URL=rediss://redis:6379"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.InsecureProtocol != 0 {
		t.Fatal("should not flag secure protocol")
	}
}

func TestNonSensitiveNoMissingPin(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web-frontend", Image: "nginx:latest"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.MissingCertPin != 0 {
		t.Fatal("non-sensitive service should not trigger missing cert pin")
	}
}

func TestFormatTextHeader(t *testing.T) {
	r := Analyze(collected(nil))
	text := FormatText(r)
	if !strings.Contains(text, "Certificate Pinning") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatTextFindings(t *testing.T) {
	svcs := []compose.Service{
		{Name: "api", Image: "myapi:latest", Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}},
	}
	r := Analyze(collected(svcs))
	text := FormatText(r)
	if !strings.Contains(text, "api") {
		t.Fatal("expected service name in text output")
	}
}

func TestMultipleFindings(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15", Environment: []string{"SSL_VERIFY=false", "SELF_SIGNED=true"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15"},
		{Name: "redis", Image: "redis:7", Environment: []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}},
		{Name: "web", Image: "nginx"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
}
