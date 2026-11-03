package ssrfaudit

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

func TestInternalURLExposedLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"BACKEND_URL=http://localhost:8080/api"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "internal_url_exposed")
	if len(findings) == 0 {
		t.Fatal("expected internal_url_exposed for localhost URL")
	}
}

func TestInternalURLExposed127(t *testing.T) {
	s := compose.Service{
		Name:        "worker",
		Image:       "python:3.12",
		Environment: []string{"CALLBACK=http://127.0.0.1:9090/hook"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "internal_url_exposed")
	if len(findings) == 0 {
		t.Fatal("expected internal_url_exposed for 127.0.0.1")
	}
}

func TestInternalURLExposed192168(t *testing.T) {
	s := compose.Service{
		Name:        "fetcher",
		Image:       "curl:latest",
		Environment: []string{"TARGET=http://192.168.1.100:3000"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "internal_url_exposed")
	if len(findings) == 0 {
		t.Fatal("expected internal_url_exposed for 192.168.x.x")
	}
}

func TestNoInternalURLForPublicAddress(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"API_URL=https://api.example.com"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "internal_url_exposed")
	if len(findings) != 0 {
		t.Fatal("public URL should not trigger internal_url_exposed")
	}
}

func TestMetadataEndpointAWS(t *testing.T) {
	s := compose.Service{
		Name:        "app",
		Image:       "python:3.12",
		Environment: []string{"METADATA=http://169.254.169.254/latest/meta-data/"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "metadata_endpoint")
	if len(findings) == 0 {
		t.Fatal("expected metadata_endpoint for AWS metadata IP")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestMetadataEndpointGCP(t *testing.T) {
	s := compose.Service{
		Name:        "worker",
		Image:       "golang:1.22",
		Environment: []string{"GCP_META=http://metadata.google.internal/computeMetadata/v1/"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "metadata_endpoint")
	if len(findings) == 0 {
		t.Fatal("expected metadata_endpoint for GCP metadata hostname")
	}
}

func TestNoMetadataForNormalService(t *testing.T) {
	s := svc("web", "nginx:latest")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "metadata_endpoint")
	if len(findings) != 0 {
		t.Fatal("service without metadata refs should not trigger metadata_endpoint")
	}
}

func TestUnrestrictedProxySquid(t *testing.T) {
	s := compose.Service{
		Name:  "proxy",
		Image: "sameersbn/squid:3.5",
		Ports: []compose.PortMapping{{TargetPort: 3128}},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_proxy")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_proxy for squid with exposed port")
	}
}

func TestUnrestrictedProxyNginx(t *testing.T) {
	s := compose.Service{
		Name:  "reverse-proxy",
		Image: "nginx:1.25",
		Ports: []compose.PortMapping{{TargetPort: 80}},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_proxy")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_proxy for nginx with exposed port 80")
	}
}

func TestNoUnrestrictedProxyWithoutPort(t *testing.T) {
	s := compose.Service{
		Name:  "internal-proxy",
		Image: "squid:latest",
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_proxy")
	if len(findings) != 0 {
		t.Fatal("proxy without exposed ports should not trigger unrestricted_proxy")
	}
}

func TestSSRFSinkNoValidationWebhook(t *testing.T) {
	s := compose.Service{
		Name:        "notifier",
		Image:       "node:20",
		Environment: []string{"WEBHOOK_URL=https://hooks.slack.com/services/abc"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "ssrf_sink_no_validation")
	if len(findings) == 0 {
		t.Fatal("expected ssrf_sink_no_validation for WEBHOOK_URL env")
	}
}

func TestSSRFSinkNoValidationCallback(t *testing.T) {
	s := compose.Service{
		Name:        "oauth",
		Image:       "keycloak:latest",
		Environment: []string{"CALLBACK_URL=https://example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "ssrf_sink_no_validation")
	if len(findings) == 0 {
		t.Fatal("expected ssrf_sink_no_validation for CALLBACK_URL env")
	}
}

func TestSSRFSinkMultiple(t *testing.T) {
	s := compose.Service{
		Name:        "gateway",
		Image:       "node:20",
		Environment: []string{"WEBHOOK_URL=x", "REDIRECT_URI=y"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "ssrf_sink_no_validation")
	if len(findings) != 2 {
		t.Fatalf("expected 2 ssrf_sink_no_validation findings, got %d", len(findings))
	}
}

func TestNoSSRFSinkForNormalEnv(t *testing.T) {
	s := compose.Service{
		Name:        "app",
		Image:       "node:20",
		Environment: []string{"NODE_ENV=production", "PORT=3000"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "ssrf_sink_no_validation")
	if len(findings) != 0 {
		t.Fatal("normal env vars should not trigger ssrf_sink_no_validation")
	}
}

func TestPrivateNetworkAccessHostProxy(t *testing.T) {
	s := compose.Service{
		Name:        "proxy",
		Image:       "haproxy:2.8",
		NetworkMode: "host",
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "private_network_access")
	if len(findings) == 0 {
		t.Fatal("expected private_network_access for proxy with host network")
	}
	if findings[0].Level != "critical" {
		t.Fatalf("expected critical severity, got %s", findings[0].Level)
	}
}

func TestPrivateNetworkAccessPrivilegedProxy(t *testing.T) {
	s := compose.Service{
		Name:       "proxy",
		Image:      "envoy:latest",
		Privileged: true,
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "private_network_access")
	if len(findings) == 0 {
		t.Fatal("expected private_network_access for privileged proxy")
	}
}

func TestNoPrivateNetworkForNonProxy(t *testing.T) {
	s := compose.Service{
		Name:        "db",
		Image:       "postgres:16",
		NetworkMode: "host",
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "private_network_access")
	if len(findings) != 0 {
		t.Fatal("non-proxy with host network should not trigger private_network_access")
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
	s := compose.Service{
		Name:        "proxy",
		Image:       "squid:latest",
		NetworkMode: "host",
		Ports:       []compose.PortMapping{{TargetPort: 3128}},
		Environment: []string{"WEBHOOK_URL=http://169.254.169.254/latest"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings")
	}
	if r.Summary.UnrestrictedProxy == 0 {
		t.Fatal("expected unrestricted_proxy count > 0")
	}
}

func TestFormatTextHeader(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "SSRF Vulnerability Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextServiceName(t *testing.T) {
	s := compose.Service{
		Name:        "my-proxy",
		Image:       "squid:latest",
		Ports:       []compose.PortMapping{{TargetPort: 3128}},
	}
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
			{Path: "docker-compose.yml", Services: []compose.Service{svc("web", "nginx:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("proxy", "squid:latest")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}
