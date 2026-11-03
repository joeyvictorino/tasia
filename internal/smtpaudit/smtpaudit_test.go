package smtpaudit

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

func TestOpenRelayPublicPort(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "docker-mailserver/docker-mailserver:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"RELAY_HOST=smtp.example.com", "PERMIT_MYNETWORKS=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "open_relay")
	if len(findings) == 0 {
		t.Fatal("expected open_relay finding for relay config on public port")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestOpenRelayLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{localhostPort(25, 25)},
		Environment: []string{"RELAY_HOST=smtp.example.com"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "open_relay")
	if len(findings) != 0 {
		t.Fatal("should not flag open_relay on localhost binding")
	}
}

func TestNoSMTPTLSPublic(t *testing.T) {
	s := compose.Service{
		Name:  "mail",
		Image: "postfix:latest",
		Ports: []compose.PortMapping{publicPort(25, 25)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_smtp_tls")
	if len(findings) == 0 {
		t.Fatal("expected no_smtp_tls for public SMTP without TLS config")
	}
	if findings[0].Level != "medium" {
		t.Fatalf("expected medium severity, got %s", findings[0].Level)
	}
}

func TestNoSMTPTLSWithTLSConfig(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"SMTP_TLS_CERT=/certs/mail.pem"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_smtp_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag no_smtp_tls when TLS is configured")
	}
}

func TestNoSMTPTLSWithSMTPSPort(t *testing.T) {
	s := compose.Service{
		Name:  "mail",
		Image: "postfix:latest",
		Ports: []compose.PortMapping{publicPort(465, 465)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_smtp_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag no_smtp_tls when SMTPS port 465 is used")
	}
}

func TestPlaintextAuthFlagged(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"SMTP_AUTH_MECHANISM=PLAIN LOGIN"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_auth")
	if len(findings) == 0 {
		t.Fatal("expected plaintext_auth finding")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestPlaintextAuthWithTLSNotFlagged(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(587, 587)},
		Environment: []string{"SMTP_AUTH_MECHANISM=PLAIN LOGIN TLS"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag plaintext_auth when TLS is mentioned")
	}
}

func TestWeakCredentialsFlagged(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"SMTP_PASSWORD=password"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_credentials")
	if len(findings) == 0 {
		t.Fatal("expected weak_credentials finding for password=password")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestWeakCredentialsAdmin(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"SMTP_PASSWORD=admin"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_credentials")
	if len(findings) == 0 {
		t.Fatal("expected weak_credentials for password=admin")
	}
}

func TestWeakCredentialsStrongPassword(t *testing.T) {
	s := compose.Service{
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"SMTP_PASSWORD=xK9$mP2!qR7wL4"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_credentials")
	if len(findings) != 0 {
		t.Fatal("should not flag strong password as weak credentials")
	}
}

func TestExposedSubmissionPort(t *testing.T) {
	s := compose.Service{
		Name:  "mail",
		Image: "postfix:latest",
		Ports: []compose.PortMapping{publicPort(587, 587)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "exposed_submission")
	if len(findings) == 0 {
		t.Fatal("expected exposed_submission for public port 587")
	}
	if findings[0].Level != "medium" {
		t.Fatalf("expected medium severity, got %s", findings[0].Level)
	}
}

func TestExposedSubmissionLocalhostNotFlagged(t *testing.T) {
	s := compose.Service{
		Name:  "mail",
		Image: "postfix:latest",
		Ports: []compose.PortMapping{localhostPort(587, 587)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "exposed_submission")
	if len(findings) != 0 {
		t.Fatal("should not flag exposed_submission on localhost")
	}
}

func TestNonSMTPServiceNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-SMTP service, got %d", r.Summary.TotalFindings)
	}
}

func TestSMTPDetectedByPort(t *testing.T) {
	s := compose.Service{
		Name:  "svc",
		Image: "myapp:latest",
		Ports: []compose.PortMapping{publicPort(25, 25)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service uses SMTP port 25")
	}
}

func TestSMTPDetectedByEnv(t *testing.T) {
	s := compose.Service{
		Name:        "svc",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"SMTP_HOST=mail.example.com"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service has SMTP in env")
	}
}

func TestMailhogDetection(t *testing.T) {
	s := compose.Service{
		Name:  "mailhog",
		Image: "mailhog/mailhog:latest",
		Ports: []compose.PortMapping{publicPort(1025, 1025), publicPort(8025, 8025)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for mailhog image")
	}
}

func TestMailpitDetection(t *testing.T) {
	s := compose.Service{
		Name:  "mailpit",
		Image: "axllent/mailpit:latest",
		Ports: []compose.PortMapping{publicPort(1025, 1025), publicPort(8025, 8025)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for mailpit image")
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
		Name:        "mail",
		Image:       "postfix:latest",
		Ports:       []compose.PortMapping{publicPort(25, 25)},
		Environment: []string{"RELAY_HOST=relay.example.com"},
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
	r := Analyze(collected(svc("mail", "postfix:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "SMTP Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{
		Name:  "my-mail-server",
		Image: "postfix:latest",
		Ports: []compose.PortMapping{publicPort(25, 25)},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-mail-server") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("mail", "postfix:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("mailhog", "mailhog/mailhog:latest")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestDockerMailServerDetection(t *testing.T) {
	s := compose.Service{
		Name:  "mailserver",
		Image: "docker.io/mailserver/docker-mailserver:latest",
		Ports: []compose.PortMapping{publicPort(25, 25), publicPort(587, 587)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for docker-mailserver image")
	}
}

func TestPort2525Detection(t *testing.T) {
	s := compose.Service{
		Name:  "smtp",
		Image: "myapp:latest",
		Ports: []compose.PortMapping{publicPort(2525, 2525)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for SMTP port 2525")
	}
}

func TestNamshiSMTPDetection(t *testing.T) {
	s := compose.Service{
		Name:  "smtp",
		Image: "namshi/smtp:latest",
		Ports: []compose.PortMapping{publicPort(25, 25)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for namshi/smtp image")
	}
}
