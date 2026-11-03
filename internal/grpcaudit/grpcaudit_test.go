package grpcaudit

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

func TestPlaintextGrpcPublicPort(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "myapp/grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"GRPC_PLAINTEXT=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_grpc")
	if len(findings) == 0 {
		t.Fatal("expected plaintext_grpc finding for public gRPC with plaintext config")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestPlaintextGrpcInsecureEnv(t *testing.T) {
	s := compose.Service{
		Name:        "svc",
		Image:       "grpc-gateway:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"GRPC_INSECURE=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_grpc")
	if len(findings) == 0 {
		t.Fatal("expected plaintext_grpc finding for insecure env")
	}
}

func TestNoPlaintextGrpcLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "myapp/grpc-server:latest",
		Ports:       []compose.PortMapping{localhostPort(50051, 50051)},
		Environment: []string{"GRPC_PLAINTEXT=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_grpc")
	if len(findings) != 0 {
		t.Fatal("should not flag plaintext_grpc on localhost binding")
	}
}

func TestNoGrpcTLSPublic(t *testing.T) {
	s := compose.Service{
		Name:  "api",
		Image: "grpc-server:latest",
		Ports: []compose.PortMapping{publicPort(50051, 50051)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_grpc_tls")
	if len(findings) == 0 {
		t.Fatal("expected no_grpc_tls for public gRPC without TLS config")
	}
}

func TestNoGrpcTLSWithTLSConfig(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"GRPC_TLS_CERT=/certs/server.pem"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_grpc_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag no_grpc_tls when TLS is configured")
	}
}

func TestInsecureGrpcReflectionPublic(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"GRPC_REFLECTION=enabled"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_grpc_reflection")
	if len(findings) == 0 {
		t.Fatal("expected insecure_grpc_reflection for public gRPC with reflection")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestReflectionNotFlaggedOnLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{localhostPort(50051, 50051)},
		Environment: []string{"GRPC_REFLECTION=enabled"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_grpc_reflection")
	if len(findings) != 0 {
		t.Fatal("should not flag reflection on localhost binding")
	}
}

func TestMissingGrpcAuthPublic(t *testing.T) {
	s := compose.Service{
		Name:  "api",
		Image: "grpc-server:latest",
		Ports: []compose.PortMapping{publicPort(50051, 50051)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_grpc_auth")
	if len(findings) == 0 {
		t.Fatal("expected missing_grpc_auth for public gRPC without auth")
	}
}

func TestMissingGrpcAuthWithInterceptor(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"AUTH_INTERCEPTOR=jwt"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_grpc_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag missing_grpc_auth with auth interceptor")
	}
}

func TestGrpcHealthNoAuth(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"GRPC_HEALTH_CHECK=enabled"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "grpc_health_no_auth")
	if len(findings) == 0 {
		t.Fatal("expected grpc_health_no_auth for public service with health check and no auth")
	}
}

func TestGrpcHealthWithAuth(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"GRPC_HEALTH_CHECK=enabled", "GRPC_AUTH_TOKEN=secret"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "grpc_health_no_auth")
	if len(findings) != 0 {
		t.Fatal("should not flag health check when auth is configured")
	}
}

func TestNonGrpcServiceNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-gRPC service, got %d", r.Summary.TotalFindings)
	}
}

func TestGrpcDetectedByPort(t *testing.T) {
	s := compose.Service{
		Name:  "svc",
		Image: "myapp:latest",
		Ports: []compose.PortMapping{publicPort(50051, 50051)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service uses gRPC port 50051")
	}
}

func TestGrpcDetectedByEnv(t *testing.T) {
	s := compose.Service{
		Name:        "svc",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"GRPC_PORT=50051"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service has GRPC in env")
	}
}

func TestOtelCollectorDetected(t *testing.T) {
	s := compose.Service{
		Name:  "otel",
		Image: "otel/opentelemetry-collector:latest",
		Ports: []compose.PortMapping{publicPort(4317, 4317)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_grpc_tls")
	if len(findings) == 0 {
		t.Fatal("expected findings for otel collector on gRPC port")
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
		Name:        "api",
		Image:       "grpc-server:latest",
		Ports:       []compose.PortMapping{publicPort(50051, 50051)},
		Environment: []string{"GRPC_REFLECTION=on"},
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
	r := Analyze(collected(svc("api", "grpc:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "gRPC Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{
		Name:  "my-grpc-api",
		Image: "grpc-server:latest",
		Ports: []compose.PortMapping{publicPort(50051, 50051)},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-grpc-api") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("api", "grpc-server:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("debug", "grpc-debug:latest")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestEnvoyGrpcDetection(t *testing.T) {
	s := compose.Service{
		Name:  "envoy",
		Image: "envoyproxy/envoy:v1.28",
		Ports: []compose.PortMapping{publicPort(9090, 9090)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for envoy with gRPC port")
	}
}

func TestHealthCheckViaHealthcheckTest(t *testing.T) {
	s := compose.Service{
		Name:  "api",
		Image: "grpc-server:latest",
		Ports: []compose.PortMapping{publicPort(50051, 50051)},
		Healthcheck: &compose.Healthcheck{
			Test: []string{"CMD", "grpc-health-probe", "-addr=:50051"},
		},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "grpc_health_no_auth")
	if len(findings) == 0 {
		t.Fatal("expected grpc_health_no_auth when healthcheck uses grpc-health-probe")
	}
}
