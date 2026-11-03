package dnstls

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

func TestPublicDNSResolverGoogle(t *testing.T) {
	s := compose.Service{Name: "web", Image: "nginx:latest", DNS: []string{"8.8.8.8"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_dns_resolver")
	if len(findings) == 0 {
		t.Fatal("expected public_dns_resolver for Google DNS 8.8.8.8")
	}
}

func TestPublicDNSResolverCloudflare(t *testing.T) {
	s := compose.Service{Name: "api", Image: "node:20", DNS: []string{"1.1.1.1"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_dns_resolver")
	if len(findings) == 0 {
		t.Fatal("expected public_dns_resolver for Cloudflare DNS 1.1.1.1")
	}
}

func TestPublicDNSResolverQuad9(t *testing.T) {
	s := compose.Service{Name: "worker", Image: "python:3.12", DNS: []string{"9.9.9.9"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_dns_resolver")
	if len(findings) == 0 {
		t.Fatal("expected public_dns_resolver for Quad9 DNS")
	}
}

func TestPrivateDNSNoPublicFinding(t *testing.T) {
	s := compose.Service{Name: "web", Image: "nginx:latest", DNS: []string{"10.0.0.53"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_dns_resolver")
	if len(findings) != 0 {
		t.Fatal("private DNS address should not trigger public_dns_resolver")
	}
}

func TestPlaintextDNS(t *testing.T) {
	s := compose.Service{Name: "web", Image: "nginx:latest", DNS: []string{"10.0.0.53"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_dns")
	if len(findings) == 0 {
		t.Fatal("expected plaintext_dns for service with DNS but no DoT config")
	}
}

func TestPlaintextDNSSuppressedWithDoTEnv(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		DNS:         []string{"10.0.0.53"},
		Environment: []string{"DNS_OVER_TLS=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_dns")
	if len(findings) != 0 {
		t.Fatal("service with DNS_OVER_TLS env should not get plaintext_dns finding")
	}
}

func TestPlaintextDNSSuppressedWithDoTResolver(t *testing.T) {
	resolver := compose.Service{
		Name:  "dns",
		Image: "cloudflare/cloudflared:latest",
		Ports: []compose.PortMapping{{TargetPort: 53}},
	}
	web := compose.Service{Name: "web", Image: "nginx:latest", DNS: []string{"10.0.0.53"}}
	r := Analyze(collected(resolver, web))
	findings := findByRule(r.Services, "plaintext_dns")
	if len(findings) != 0 {
		t.Fatal("plaintext_dns should be suppressed when DoT resolver is in the stack")
	}
}

func TestMissingDNSConfig(t *testing.T) {
	s := svc("web", "nginx:latest")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_dns_config")
	if len(findings) == 0 {
		t.Fatal("expected missing_dns_config for service without explicit DNS")
	}
}

func TestMissingDNSConfigSuppressedOnHostNetwork(t *testing.T) {
	s := compose.Service{Name: "web", Image: "nginx:latest", NetworkMode: "host"}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_dns_config")
	if len(findings) != 0 {
		t.Fatal("host network mode should suppress missing_dns_config")
	}
}

func TestMissingDNSConfigSuppressedWithDoTResolver(t *testing.T) {
	resolver := compose.Service{
		Name:  "dns",
		Image: "pihole/pihole:latest",
		Ports: []compose.PortMapping{{TargetPort: 53}},
	}
	web := svc("web", "nginx:latest")
	r := Analyze(collected(resolver, web))
	findings := findByRule(r.Services, "missing_dns_config")
	if len(findings) != 0 {
		t.Fatal("missing_dns_config should be suppressed when DoT resolver is in the stack")
	}
}

func TestDNSOverTLSAvailable(t *testing.T) {
	s := compose.Service{
		Name:  "dns",
		Image: "cloudflare/cloudflared:latest",
		Ports: []compose.PortMapping{{TargetPort: 853}},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "dns_over_tls_available")
	if len(findings) == 0 {
		t.Fatal("expected dns_over_tls_available for cloudflared")
	}
}

func TestDNSOverTLSAvailableUnbound(t *testing.T) {
	s := svc("resolver", "mvance/unbound:latest")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "dns_over_tls_available")
	if len(findings) == 0 {
		t.Fatal("expected dns_over_tls_available for unbound resolver")
	}
}

func TestDNSOverTLSAvailableCoreDNS(t *testing.T) {
	s := svc("dns", "coredns/coredns:1.11")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "dns_over_tls_available")
	if len(findings) == 0 {
		t.Fatal("expected dns_over_tls_available for coredns")
	}
}

func TestInsecureDNSWithSecrets(t *testing.T) {
	s := compose.Service{
		Name:  "vault",
		Image: "hashicorp/vault:1.15",
		DNS:   []string{"8.8.8.8"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_dns_with_secrets")
	if len(findings) == 0 {
		t.Fatal("expected insecure_dns_with_secrets for vault with public DNS")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestInsecureDNSWithSecretsPostgres(t *testing.T) {
	s := compose.Service{
		Name:  "db",
		Image: "postgres:16",
		DNS:   []string{"1.1.1.1"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_dns_with_secrets")
	if len(findings) == 0 {
		t.Fatal("expected insecure_dns_with_secrets for postgres with public DNS")
	}
}

func TestNoInsecureDNSWithDoTEnv(t *testing.T) {
	s := compose.Service{
		Name:        "vault",
		Image:       "hashicorp/vault:1.15",
		DNS:         []string{"8.8.8.8"},
		Environment: []string{"DNS_OVER_TLS=enabled"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_dns_with_secrets")
	if len(findings) != 0 {
		t.Fatal("vault with DoT env should not get insecure_dns_with_secrets")
	}
}

func TestNonSensitiveServiceNoSecretFinding(t *testing.T) {
	s := compose.Service{
		Name:  "web",
		Image: "nginx:latest",
		DNS:   []string{"8.8.8.8"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_dns_with_secrets")
	if len(findings) != 0 {
		t.Fatal("non-sensitive service should not get insecure_dns_with_secrets")
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
		Name:  "db",
		Image: "postgres:16",
		DNS:   []string{"8.8.8.8"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected at least 1 finding")
	}
	if r.Summary.PublicDNSResolver == 0 {
		t.Fatal("expected public_dns_resolver count > 0")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "DNS-over-TLS Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{Name: "my-resolver", Image: "coredns/coredns:1.11"}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-resolver") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("web", "nginx:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("dns", "coredns/coredns:1.11")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleDNSEntries(t *testing.T) {
	s := compose.Service{
		Name:  "web",
		Image: "nginx:latest",
		DNS:   []string{"8.8.8.8", "1.1.1.1"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_dns_resolver")
	if len(findings) != 2 {
		t.Fatalf("expected 2 public_dns_resolver findings for two public DNS entries, got %d", len(findings))
	}
}
