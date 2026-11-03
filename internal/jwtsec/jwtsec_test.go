package jwtsec

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

func TestWeakAlgorithmNone(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_ALGORITHM=none", "JWT_SECRET=mysecretkey12345678"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_jwt_algorithm")
	if len(findings) == 0 {
		t.Fatal("expected weak_jwt_algorithm finding for algorithm 'none'")
	}
	if findings[0].Level != "critical" {
		t.Fatalf("expected critical severity for 'none' algorithm, got %s", findings[0].Level)
	}
}

func TestWeakAlgorithmHS256(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_ALGORITHM=HS256", "JWT_SECRET=mysecretkey12345678"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_jwt_algorithm")
	if len(findings) == 0 {
		t.Fatal("expected weak_jwt_algorithm finding for HS256")
	}
	if findings[0].Level != "medium" {
		t.Fatalf("expected medium severity for HS256, got %s", findings[0].Level)
	}
}

func TestStrongAlgorithmRS256(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_ALGORITHM=RS256", "JWT_SECRET=mysecretkey12345678"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_jwt_algorithm")
	if len(findings) != 0 {
		t.Fatal("should not flag RS256 as weak algorithm")
	}
}

func TestStrongAlgorithmES256(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_ALGORITHM=ES256", "JWT_SECRET=mysecretkey12345678"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_jwt_algorithm")
	if len(findings) != 0 {
		t.Fatal("should not flag ES256 as weak algorithm")
	}
}

func TestNoJWTExpiry(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_jwt_expiry")
	if len(findings) == 0 {
		t.Fatal("expected no_jwt_expiry finding when no expiry config")
	}
}

func TestWithJWTExpiry(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here", "JWT_EXPIRY=3600"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_jwt_expiry")
	if len(findings) != 0 {
		t.Fatal("should not flag no_jwt_expiry when JWT_EXPIRY is set")
	}
}

func TestWithTokenTTL(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here", "TOKEN_TTL=1h"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_jwt_expiry")
	if len(findings) != 0 {
		t.Fatal("should not flag no_jwt_expiry when TOKEN_TTL is set")
	}
}

func TestHardcodedSecretWeak(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=secret"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "hardcoded_jwt_secret")
	if len(findings) == 0 {
		t.Fatal("expected hardcoded_jwt_secret for weak secret 'secret'")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestHardcodedSecretShort(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=abc"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "hardcoded_jwt_secret")
	if len(findings) == 0 {
		t.Fatal("expected hardcoded_jwt_secret for short secret")
	}
}

func TestStrongSecretNoFinding(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=a-very-strong-random-secret-key-256-bits-long"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "hardcoded_jwt_secret")
	if len(findings) != 0 {
		t.Fatal("should not flag strong secret as hardcoded")
	}
}

func TestInsecureAudiencePublic(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_jwt_audience")
	if len(findings) == 0 {
		t.Fatal("expected insecure_jwt_audience for public service without audience config")
	}
}

func TestAudienceConfiguredNoFinding(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here", "JWT_AUDIENCE=my-api"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_jwt_audience")
	if len(findings) != 0 {
		t.Fatal("should not flag insecure_jwt_audience when JWT_AUDIENCE is set")
	}
}

func TestNoIssuerCheckPublic(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_jwt_issuer_check")
	if len(findings) == 0 {
		t.Fatal("expected no_jwt_issuer_check for public service without issuer")
	}
}

func TestIssuerConfiguredNoFinding(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here", "JWT_ISSUER=my-auth-server"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_jwt_issuer_check")
	if len(findings) != 0 {
		t.Fatal("should not flag no_jwt_issuer_check when JWT_ISSUER is set")
	}
}

func TestNoAudienceOnLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{localhostPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_jwt_audience")
	if len(findings) != 0 {
		t.Fatal("should not flag insecure_jwt_audience on localhost binding")
	}
}

func TestNonJWTServiceNoFindings(t *testing.T) {
	s := svc("postgres", "postgres:15")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-JWT service, got %d", r.Summary.TotalFindings)
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
		Name:        "auth",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=secret", "JWT_ALGORITHM=none"},
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
	s := compose.Service{
		Name:        "auth",
		Image:       "myapp:latest",
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "JWT Configuration Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{
		Name:        "my-jwt-service",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-jwt-service") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{{
				Name: "auth", Image: "myapp:latest",
				Environment: []string{"JWT_SECRET=strong-enough-secret-key-here"},
			}}},
			{Path: "docker-compose.prod.yml", Services: []compose.Service{{
				Name: "auth-v2", Image: "myapp:v2",
				Environment: []string{"JWT_KEY=another-strong-key-for-prod"},
			}}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}
