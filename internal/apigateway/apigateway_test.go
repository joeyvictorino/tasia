package apigateway

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

func TestGatewayNoAuth(t *testing.T) {
	gw := compose.Service{
		Name:  "kong",
		Image: "kong:latest",
		Ports: []compose.PortMapping{publicPort(8000, 8000)},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_auth")
	if len(findings) == 0 {
		t.Fatal("expected gateway_no_auth for gateway without auth plugins")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestGatewayWithAuth(t *testing.T) {
	gw := compose.Service{
		Name:        "kong",
		Image:       "kong:latest",
		Ports:       []compose.PortMapping{publicPort(8000, 8000)},
		Environment: []string{"AUTH_PLUGIN=key-auth"},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag gateway with auth configured")
	}
}

func TestGatewayNoRateLimit(t *testing.T) {
	gw := compose.Service{
		Name:  "traefik",
		Image: "traefik:latest",
		Ports: []compose.PortMapping{publicPort(80, 80)},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_rate_limit")
	if len(findings) == 0 {
		t.Fatal("expected gateway_no_rate_limit for gateway without rate limiting")
	}
}

func TestGatewayWithRateLimit(t *testing.T) {
	gw := compose.Service{
		Name:        "traefik",
		Image:       "traefik:latest",
		Ports:       []compose.PortMapping{publicPort(80, 80)},
		Environment: []string{"RATE_LIMIT_AVERAGE=100"},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_rate_limit")
	if len(findings) != 0 {
		t.Fatal("should not flag gateway with rate limiting configured")
	}
}

func TestGatewayNoTLS(t *testing.T) {
	gw := compose.Service{
		Name:  "kong",
		Image: "kong:latest",
		Ports: []compose.PortMapping{publicPort(8000, 8000)},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_tls")
	if len(findings) == 0 {
		t.Fatal("expected gateway_no_tls for gateway without TLS")
	}
}

func TestGatewayWithTLS(t *testing.T) {
	gw := compose.Service{
		Name:        "kong",
		Image:       "kong:latest",
		Ports:       []compose.PortMapping{publicPort(443, 443)},
		Environment: []string{"SSL_CERT_PATH=/certs/server.pem"},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag gateway with TLS configured")
	}
}

func TestDirectExposure(t *testing.T) {
	gw := compose.Service{
		Name:        "kong",
		Image:       "kong:latest",
		Ports:       []compose.PortMapping{publicPort(8000, 8000)},
		Environment: []string{"AUTH_PLUGIN=key-auth", "SSL_CERT=/cert.pem", "RATE_LIMIT_AVG=10"},
	}
	backend := compose.Service{
		Name:  "api",
		Image: "node:18",
		Ports: []compose.PortMapping{publicPort(3000, 3000)},
	}
	r := Analyze(collected(gw, backend))
	findings := findByRule(r.Services, "direct_exposure")
	if len(findings) == 0 {
		t.Fatal("expected direct_exposure for backend with public port alongside gateway")
	}
}

func TestBackendLocalOnlyNotFlagged(t *testing.T) {
	gw := compose.Service{
		Name:  "kong",
		Image: "kong:latest",
		Ports: []compose.PortMapping{publicPort(8000, 8000)},
	}
	backend := compose.Service{
		Name:  "api",
		Image: "node:18",
		Ports: []compose.PortMapping{localhostPort(3000, 3000)},
	}
	r := Analyze(collected(gw, backend))
	findings := findByRule(r.Services, "direct_exposure")
	if len(findings) != 0 {
		t.Fatal("should not flag backend on localhost when gateway present")
	}
}

func TestNoGatewayPresent(t *testing.T) {
	backend := compose.Service{
		Name:  "api",
		Image: "python:3.11",
		Ports: []compose.PortMapping{publicPort(8000, 8000)},
	}
	r := Analyze(collected(backend))
	findings := findByRule(r.Services, "no_gateway")
	if len(findings) == 0 {
		t.Fatal("expected no_gateway for exposed backend without gateway")
	}
}

func TestNoGatewayLocalhost(t *testing.T) {
	backend := compose.Service{
		Name:  "api",
		Image: "python:3.11",
		Ports: []compose.PortMapping{localhostPort(8000, 8000)},
	}
	r := Analyze(collected(backend))
	findings := findByRule(r.Services, "no_gateway")
	if len(findings) != 0 {
		t.Fatal("should not flag no_gateway when backend is on localhost")
	}
}

func TestNonAPIServiceNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-API service, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextHeader(t *testing.T) {
	r := Analyze(collected(svc("kong", "kong:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "API Gateway Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	gw := compose.Service{
		Name:  "kong",
		Image: "kong:latest",
		Ports: []compose.PortMapping{publicPort(8000, 8000)},
	}
	backend := compose.Service{
		Name:  "api",
		Image: "fastapi:latest",
		Ports: []compose.PortMapping{publicPort(8080, 8080)},
	}
	r := Analyze(collected(gw, backend))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings")
	}
}

func TestAPISIXDetected(t *testing.T) {
	gw := compose.Service{
		Name:  "apisix",
		Image: "apache/apisix:latest",
		Ports: []compose.PortMapping{publicPort(9080, 9080)},
	}
	r := Analyze(collected(gw))
	if !isGateway(gw) {
		t.Fatal("APISIX should be detected as a gateway")
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for APISIX without auth")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{{
				Name:  "gateway",
				Image: "kong:latest",
				Ports: []compose.PortMapping{publicPort(8000, 8000)},
			}}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{{
				Name:  "api",
				Image: "node:18",
				Ports: []compose.PortMapping{publicPort(3000, 3000)},
			}}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestGatewayLocalhostNotFlagged(t *testing.T) {
	gw := compose.Service{
		Name:  "kong",
		Image: "kong:latest",
		Ports: []compose.PortMapping{localhostPort(8000, 8000)},
	}
	r := Analyze(collected(gw))
	findings := findByRule(r.Services, "gateway_no_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag gateway on localhost")
	}
}

func TestEnvoyDetectedAsGateway(t *testing.T) {
	gw := compose.Service{
		Name:  "envoy",
		Image: "envoyproxy/envoy:v1.28",
		Ports: []compose.PortMapping{publicPort(8080, 8080)},
	}
	if !isGateway(gw) {
		t.Fatal("envoy should be detected as a gateway")
	}
}

func TestGatewayDetectedByEnv(t *testing.T) {
	gw := compose.Service{
		Name:        "proxy",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"API_GATEWAY_MODE=true"},
	}
	if !isGateway(gw) {
		t.Fatal("service with API_GATEWAY env should be detected as gateway")
	}
}
