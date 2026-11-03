package proxyproto

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

func svcWithPorts(name, image string, ports ...compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Ports: ports}
}

func publicPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target, Raw: "0.0.0.0:" + strings.Repeat("0", 0)}
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

func TestMissingProxyProtoOnPublicNginx(t *testing.T) {
	s := svcWithPorts("proxy", "nginx:latest", publicPort(80, 80))
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) == 0 {
		t.Fatal("expected missing_proxy_proto finding for public nginx without proxy protocol config")
	}
}

func TestMissingProxyProtoOnPublicHAProxy(t *testing.T) {
	s := svcWithPorts("lb", "haproxy:2.8", publicPort(443, 443))
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) == 0 {
		t.Fatal("expected missing_proxy_proto for public haproxy")
	}
}

func TestMissingProxyProtoOnPublicTraefik(t *testing.T) {
	s := svcWithPorts("edge", "traefik:v3", publicPort(80, 80))
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) == 0 {
		t.Fatal("expected missing_proxy_proto for public traefik")
	}
}

func TestNoFindingWhenProxyHasConfig(t *testing.T) {
	s := compose.Service{
		Name:        "proxy",
		Image:       "nginx:latest",
		Ports:       []compose.PortMapping{publicPort(80, 80)},
		Environment: []string{"PROXY_PROTOCOL=v2"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) != 0 {
		t.Fatal("proxy with PROXY_PROTOCOL env should not get missing_proxy_proto finding")
	}
}

func TestNoFindingForLocalhostProxy(t *testing.T) {
	s := svcWithPorts("proxy", "nginx:latest", localhostPort(80, 80))
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) != 0 {
		t.Fatal("localhost-bound proxy should not get missing_proxy_proto finding")
	}
}

func TestTrustedProxyConcernsForBackend(t *testing.T) {
	proxy := svc("proxy", "nginx:latest")
	backend := svc("api", "node:20")
	r := Analyze(collected(proxy, backend))
	findings := findByRule(r.Services, "trusted_proxy_concerns")
	if len(findings) == 0 {
		t.Fatal("expected trusted_proxy_concerns for backend behind proxy without trusted proxy config")
	}
}

func TestNoTrustedProxyConcernsWhenConfigured(t *testing.T) {
	proxy := svc("proxy", "nginx:latest")
	backend := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"TRUSTED_PROXIES=172.16.0.0/12"},
	}
	r := Analyze(collected(proxy, backend))
	findings := findByRule(r.Services, "trusted_proxy_concerns")
	if len(findings) != 0 {
		t.Fatal("backend with trusted proxy config should not get trusted_proxy_concerns")
	}
}

func TestNoTrustedProxyConcernsWithoutProxy(t *testing.T) {
	backend := svc("api", "node:20")
	r := Analyze(collected(backend))
	findings := findByRule(r.Services, "trusted_proxy_concerns")
	if len(findings) != 0 {
		t.Fatal("backend without any proxy in stack should not get trusted_proxy_concerns")
	}
}

func TestUnprotectedUpstreamHeaders(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "python:3.12",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"USE_X_FORWARDED_FOR=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unprotected_upstream_headers")
	if len(findings) == 0 {
		t.Fatal("expected unprotected_upstream_headers for directly-exposed backend using forwarding headers")
	}
}

func TestUnprotectedUpstreamHeadersHighSeverity(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "python:3.12",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"X_REAL_IP=enabled"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unprotected_upstream_headers")
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestNoUnprotectedHeadersWhenProxyPresent(t *testing.T) {
	proxy := svc("proxy", "nginx:latest")
	backend := compose.Service{
		Name:        "api",
		Image:       "python:3.12",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"USE_X_FORWARDED_FOR=true"},
	}
	r := Analyze(collected(proxy, backend))
	findings := findByRule(r.Services, "unprotected_upstream_headers")
	if len(findings) != 0 {
		t.Fatal("should not flag unprotected_upstream_headers when proxy is present")
	}
}

func TestExposedRealIP(t *testing.T) {
	proxy := svc("proxy", "nginx:latest")
	backend := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"X_REAL_IP=from_header"},
	}
	r := Analyze(collected(proxy, backend))
	findings := findByRule(r.Services, "exposed_real_ip")
	if len(findings) == 0 {
		t.Fatal("expected exposed_real_ip for backend using forwarding headers without trusted proxy config")
	}
}

func TestNoExposedRealIPWithTrustedConfig(t *testing.T) {
	proxy := svc("proxy", "nginx:latest")
	backend := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"X_REAL_IP=from_header", "TRUST_PROXY=172.16.0.0/12"},
	}
	r := Analyze(collected(proxy, backend))
	findings := findByRule(r.Services, "exposed_real_ip")
	if len(findings) != 0 {
		t.Fatal("backend with trust_proxy should not get exposed_real_ip")
	}
}

func TestNonProxyNonBackendNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-proxy/non-backend service, got %d", r.Summary.TotalFindings)
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
	proxy := svcWithPorts("proxy", "nginx:latest", publicPort(80, 80))
	backend := svc("api", "node:20")
	r := Analyze(collected(proxy, backend))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected at least 1 finding")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("proxy", "nginx:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "Proxy Protocol Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := svcWithPorts("my-proxy", "nginx:latest", publicPort(80, 80))
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-proxy") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("proxy", "nginx:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("api", "node:20")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestEnvoyProxy(t *testing.T) {
	s := svcWithPorts("envoy", "envoyproxy/envoy:v1.28", publicPort(8080, 8080))
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) == 0 {
		t.Fatal("expected missing_proxy_proto for public envoy")
	}
}

func TestCaddyProxy(t *testing.T) {
	s := svcWithPorts("caddy", "caddy:2", publicPort(443, 443))
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_proxy_proto")
	if len(findings) == 0 {
		t.Fatal("expected missing_proxy_proto for public caddy")
	}
}
