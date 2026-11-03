package webhooksec

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

func TestNoWebhookSecretDetected(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Ports:       []compose.PortMapping{publicPort(9000, 9000)},
		Environment: []string{"WEBHOOK_URL=https://example.com/hook"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_webhook_secret")
	if len(findings) == 0 {
		t.Fatal("expected no_webhook_secret finding for webhook service without signing secret")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestNoWebhookSecretWithSecretConfigured(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Environment: []string{"WEBHOOK_SECRET=abc123", "WEBHOOK_URL=https://example.com/hook"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_webhook_secret")
	if len(findings) != 0 {
		t.Fatal("should not flag no_webhook_secret when signing secret is configured")
	}
}

func TestInsecureWebhookURLDetected(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "svix:latest",
		Environment: []string{"WEBHOOK_URL=http://insecure.example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_webhook_url")
	if len(findings) == 0 {
		t.Fatal("expected insecure_webhook_url finding for HTTP webhook URL")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestSecureWebhookURLNoFinding(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "svix:latest",
		Environment: []string{"WEBHOOK_URL=https://secure.example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_webhook_url")
	if len(findings) != 0 {
		t.Fatal("should not flag insecure_webhook_url for HTTPS URL")
	}
}

func TestPublicWebhookNoAuthDetected(t *testing.T) {
	s := compose.Service{
		Name:        "receiver",
		Image:       "hookdeck:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"WEBHOOK_ENDPOINT=/hooks"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_webhook_no_auth")
	if len(findings) == 0 {
		t.Fatal("expected public_webhook_no_auth for public webhook with no auth")
	}
}

func TestPublicWebhookWithAuthNoFinding(t *testing.T) {
	s := compose.Service{
		Name:        "receiver",
		Image:       "hookdeck:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"WEBHOOK_ENDPOINT=/hooks", "WEBHOOK_AUTH=bearer_token"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_webhook_no_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag public_webhook_no_auth when auth is configured")
	}
}

func TestPublicWebhookWithSecretNoAuthFinding(t *testing.T) {
	s := compose.Service{
		Name:        "receiver",
		Image:       "hookdeck:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"WEBHOOK_ENDPOINT=/hooks", "WEBHOOK_SECRET=s3cret"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "public_webhook_no_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag public_webhook_no_auth when webhook secret is configured")
	}
}

func TestWebhookNoTLSPublic(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Ports:       []compose.PortMapping{publicPort(9000, 9000)},
		Environment: []string{"WEBHOOK_URL=https://example.com/hook"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "webhook_no_tls")
	if len(findings) == 0 {
		t.Fatal("expected webhook_no_tls for public webhook without TLS config")
	}
}

func TestWebhookWithTLSNoFinding(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Ports:       []compose.PortMapping{publicPort(9000, 9000)},
		Environment: []string{"WEBHOOK_URL=https://example.com/hook", "TLS_CERT=/certs/server.pem"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "webhook_no_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag webhook_no_tls when TLS is configured")
	}
}

func TestWebhookNoTLSLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Ports:       []compose.PortMapping{localhostPort(9000, 9000)},
		Environment: []string{"WEBHOOK_URL=https://example.com/hook"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "webhook_no_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag webhook_no_tls on localhost binding")
	}
}

func TestWebhookReplayVulnDetected(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Environment: []string{"WEBHOOK_URL=https://example.com/hook", "WEBHOOK_SECRET=abc123"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "webhook_replay_vuln")
	if len(findings) == 0 {
		t.Fatal("expected webhook_replay_vuln when secret present but no replay protection")
	}
	if findings[0].Level != "low" {
		t.Fatalf("expected low severity, got %s", findings[0].Level)
	}
}

func TestWebhookReplayProtected(t *testing.T) {
	s := compose.Service{
		Name:  "hooks",
		Image: "webhook:latest",
		Environment: []string{
			"WEBHOOK_URL=https://example.com/hook",
			"WEBHOOK_SECRET=abc123",
			"WEBHOOK_TIMESTAMP_TOLERANCE=300",
		},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "webhook_replay_vuln")
	if len(findings) != 0 {
		t.Fatal("should not flag webhook_replay_vuln with timestamp tolerance configured")
	}
}

func TestNonWebhookServiceNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-webhook service, got %d", r.Summary.TotalFindings)
	}
}

func TestWebhookDetectedByEnvKey(t *testing.T) {
	s := compose.Service{
		Name:        "app",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"WEBHOOK_CALLBACK=https://example.com/cb"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service has webhook env key")
	}
}

func TestWebhookDetectedByImage(t *testing.T) {
	s := compose.Service{
		Name:  "relay",
		Image: "webhook-relay:latest",
		Ports: []compose.PortMapping{publicPort(8080, 8080)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service uses webhook image")
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
		Name:        "hooks",
		Image:       "webhook:latest",
		Ports:       []compose.PortMapping{publicPort(9000, 9000)},
		Environment: []string{"WEBHOOK_URL=http://example.com/hook"},
	}
	s2 := svc("redis", "redis:7")
	r := Analyze(collected(s1, s2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected at least 1 finding")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("hooks", "webhook:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "Webhook Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{
		Name:        "my-webhook-receiver",
		Image:       "webhook:latest",
		Ports:       []compose.PortMapping{publicPort(9000, 9000)},
		Environment: []string{"WEBHOOK_URL=https://example.com/hook"},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-webhook-receiver") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("hooks", "webhook:latest")}},
			{Path: "docker-compose.prod.yml", Services: []compose.Service{svc("relay", "svix:latest")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestNgrokWebhookDetection(t *testing.T) {
	s := compose.Service{
		Name:        "tunnel",
		Image:       "ngrok/ngrok:latest",
		Ports:       []compose.PortMapping{publicPort(4040, 4040)},
		Environment: []string{"WEBHOOK_URL=https://example.ngrok.io/hook"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for ngrok webhook service")
	}
}

func TestSigningSecretVariant(t *testing.T) {
	s := compose.Service{
		Name:        "hooks",
		Image:       "webhook:latest",
		Environment: []string{"SIGNING_SECRET=hmac256key", "WEBHOOK_URL=https://example.com/hook"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_webhook_secret")
	if len(findings) != 0 {
		t.Fatal("should not flag no_webhook_secret when SIGNING_SECRET is set")
	}
}
