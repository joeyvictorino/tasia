package tlsversion

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path:     "docker-compose.yml",
			Services: services,
		}},
	}
}

func svc(name, image string) compose.Service {
	return compose.Service{Name: name, Image: image}
}

func publicPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target}
}

func localhostPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target, HostIP: "127.0.0.1"}
}

func findByRule(services []ServiceResult, rule string) []Finding {
	var found []Finding
	for _, sr := range services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				found = append(found, f)
			}
		}
	}
	return found
}

func TestSSLv3EnabledCritical(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_PROTOCOLS=SSLv3 TLSv1.2"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "sslv3_enabled")
	if len(findings) == 0 {
		t.Fatal("expected sslv3_enabled finding")
	}
	if findings[0].Level != "critical" {
		t.Fatalf("expected critical severity, got %s", findings[0].Level)
	}
}

func TestSSLv2EnabledCritical(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "apache:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_PROTOCOL=SSLv2"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "sslv3_enabled")
	if len(findings) == 0 {
		t.Fatal("expected sslv3_enabled finding for SSLv2")
	}
}

func TestWeakTLSv10(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"TLS_MIN_VERSION=TLSv1.0"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_tls_version")
	if len(findings) == 0 {
		t.Fatal("expected weak_tls_version for TLSv1.0")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestWeakTLSv11(t *testing.T) {
	s := compose.Service{
		Name:        "proxy",
		Image:       "haproxy:2.8",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_MIN_PROTO=TLSv1.1"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_tls_version")
	if len(findings) == 0 {
		t.Fatal("expected weak_tls_version for TLSv1.1")
	}
}

func TestTLS12NotFlagged(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"TLS_MIN_VERSION=TLSv1.2"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_tls_version")
	if len(findings) != 0 {
		t.Fatal("TLSv1.2 should not be flagged as weak")
	}
	sslFindings := findByRule(r.Services, "sslv3_enabled")
	if len(sslFindings) != 0 {
		t.Fatal("TLSv1.2 should not be flagged as SSL")
	}
}

func TestWeakCipherRC4(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_CIPHER_SUITE=RC4-SHA:AES256"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_cipher_suite")
	if len(findings) == 0 {
		t.Fatal("expected weak_cipher_suite for RC4")
	}
}

func TestWeakCipherDES(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_CIPHER_LIST=DES-CBC3-SHA"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_cipher_suite")
	if len(findings) == 0 {
		t.Fatal("expected weak_cipher_suite for DES")
	}
}

func TestWeakCipherNULL(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "traefik:v3",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"TLS_CIPHER_SUITES=NULL-SHA256"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_cipher_suite")
	if len(findings) == 0 {
		t.Fatal("expected weak_cipher_suite for NULL cipher")
	}
}

func TestStrongCipherNotFlagged(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_CIPHER_SUITE=ECDHE-RSA-AES256-GCM-SHA384"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_cipher_suite")
	if len(findings) != 0 {
		t.Fatal("strong cipher should not be flagged")
	}
}

func TestMissingMinVersionPublic(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_CERTIFICATE=/certs/server.pem"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_min_version")
	if len(findings) == 0 {
		t.Fatal("expected missing_min_version for TLS-configured service without min version")
	}
}

func TestMissingMinVersionWithMinConfigured(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_CERTIFICATE=/certs/server.pem", "TLS_MIN_VERSION=1.2"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_min_version")
	if len(findings) != 0 {
		t.Fatal("should not flag missing_min_version when min version is configured")
	}
}

func TestTLSNotEnforcedHTTP(t *testing.T) {
	s := compose.Service{
		Name:  "web",
		Image: "nginx:latest",
		Ports: []compose.PortMapping{publicPort(80, 80)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "tls_not_enforced")
	if len(findings) == 0 {
		t.Fatal("expected tls_not_enforced for nginx on port 80 without TLS")
	}
}

func TestTLSNotEnforcedPostgres(t *testing.T) {
	s := compose.Service{
		Name:  "db",
		Image: "postgres:16",
		Ports: []compose.PortMapping{publicPort(5432, 5432)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "tls_not_enforced")
	if len(findings) == 0 {
		t.Fatal("expected tls_not_enforced for postgres on public port 5432")
	}
}

func TestTLSNotEnforcedRedis(t *testing.T) {
	s := compose.Service{
		Name:  "cache",
		Image: "redis:7",
		Ports: []compose.PortMapping{publicPort(6379, 6379)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "tls_not_enforced")
	if len(findings) == 0 {
		t.Fatal("expected tls_not_enforced for redis on public port 6379")
	}
}

func TestTLSNotEnforcedLocalhostNotFlagged(t *testing.T) {
	s := compose.Service{
		Name:  "db",
		Image: "postgres:16",
		Ports: []compose.PortMapping{localhostPort(5432, 5432)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "tls_not_enforced")
	if len(findings) != 0 {
		t.Fatal("should not flag tls_not_enforced on localhost binding")
	}
}

func TestNonTLSAwareServiceNoFindings(t *testing.T) {
	s := svc("worker", "myapp/worker:latest")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for non-TLS-aware service, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s1 := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_PROTOCOLS=SSLv3"},
	}
	s2 := svc("worker", "myapp:latest")
	r := Analyze(collected(s1, s2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SSLv3Enabled == 0 {
		t.Fatal("expected SSLv3Enabled count > 0")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "TLS Version Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{
		Name:  "my-web-server",
		Image: "nginx:latest",
		Ports: []compose.PortMapping{publicPort(80, 80)},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-web-server") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("web", "nginx:latest")}},
			{Path: "docker-compose.prod.yml", Services: []compose.Service{svc("db", "postgres:16")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestMySQLPublicNoTLS(t *testing.T) {
	s := compose.Service{
		Name:  "db",
		Image: "mysql:8",
		Ports: []compose.PortMapping{publicPort(3306, 3306)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "tls_not_enforced")
	if len(findings) == 0 {
		t.Fatal("expected tls_not_enforced for mysql on public port 3306")
	}
}

func TestMongoPublicNoTLS(t *testing.T) {
	s := compose.Service{
		Name:  "mongo",
		Image: "mongo:7",
		Ports: []compose.PortMapping{publicPort(27017, 27017)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "tls_not_enforced")
	if len(findings) == 0 {
		t.Fatal("expected tls_not_enforced for mongo on public port 27017")
	}
}
