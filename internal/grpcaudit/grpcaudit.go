package grpcaudit

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices           int `json:"total_services"`
	TotalFindings           int `json:"total_findings"`
	PlaintextGrpc           int `json:"plaintext_grpc"`
	NoGrpcTLS               int `json:"no_grpc_tls"`
	InsecureGrpcReflection  int `json:"insecure_grpc_reflection"`
	MissingGrpcAuth         int `json:"missing_grpc_auth"`
	GrpcHealthNoAuth        int `json:"grpc_health_no_auth"`
}

var grpcPorts = []int{50051, 50052, 50053, 9090, 4317, 4318}

var grpcImages = []string{
	"grpc", "envoyproxy/envoy", "grpc-gateway", "buf",
	"connectrpc", "protobuf", "otel/opentelemetry-collector",
}

func isGrpcService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range grpcImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "grpc") {
			return true
		}
	}
	for _, p := range svc.Ports {
		for _, gp := range grpcPorts {
			if p.TargetPort == gp {
				return true
			}
		}
	}
	return false
}

func hasGrpcTLS(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "grpc_tls") ||
			strings.Contains(lower, "grpc_ssl") ||
			strings.Contains(lower, "grpc_cert") ||
			strings.Contains(lower, "grpc_key") ||
			strings.Contains(lower, "tls_cert") ||
			strings.Contains(lower, "ssl_cert") ||
			strings.Contains(lower, "server_cert") {
			return true
		}
	}
	return false
}

func hasGrpcReflection(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "grpc_reflection") ||
			strings.Contains(lower, "reflection_service") ||
			strings.Contains(lower, "enable_reflection") {
			return true
		}
	}
	return false
}

func hasGrpcAuth(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "grpc_auth") ||
			strings.Contains(lower, "grpc_token") ||
			strings.Contains(lower, "grpc_api_key") ||
			strings.Contains(lower, "interceptor") ||
			strings.Contains(lower, "grpc_credentials") ||
			strings.Contains(lower, "auth_interceptor") {
			return true
		}
	}
	return false
}

func hasGrpcHealth(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "grpc_health") ||
			strings.Contains(lower, "health_check_service") {
			return true
		}
	}
	if svc.Healthcheck != nil {
		for _, t := range svc.Healthcheck.Test {
			lower := strings.ToLower(t)
			if strings.Contains(lower, "grpc_health") || strings.Contains(lower, "grpc-health") {
				return true
			}
		}
	}
	return false
}

func hasPublicPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func hasPlaintextEnv(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "grpc_plaintext") ||
			strings.Contains(lower, "insecure=true") ||
			strings.Contains(lower, "grpc_insecure") ||
			strings.Contains(lower, "use_plaintext") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isGrpcService(svc) {
		return sr
	}

	if hasPlaintextEnv(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "plaintext_grpc",
			Message: fmt.Sprintf("gRPC service '%s' is configured for plaintext communication on a public port; gRPC traffic should use TLS to prevent interception", svc.Name),
		})
	}

	if !hasGrpcTLS(svc) && hasPublicPort(svc) && !hasPlaintextEnv(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_grpc_tls",
			Message: fmt.Sprintf("gRPC service '%s' is publicly exposed but has no TLS configuration; consider enabling gRPC TLS to encrypt traffic", svc.Name),
		})
	}

	if hasGrpcReflection(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "insecure_grpc_reflection",
			Message: fmt.Sprintf("gRPC service '%s' has reflection enabled on a public port; reflection exposes service schemas and should be disabled in production", svc.Name),
		})
	}

	if !hasGrpcAuth(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_grpc_auth",
			Message: fmt.Sprintf("gRPC service '%s' is publicly exposed without authentication interceptors; unauthenticated gRPC endpoints allow unauthorized access", svc.Name),
		})
	}

	if hasGrpcHealth(svc) && !hasGrpcAuth(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "grpc_health_no_auth",
			Message: fmt.Sprintf("gRPC service '%s' exposes health check service without authentication; health endpoints can leak operational status to attackers", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "plaintext_grpc":
				s.PlaintextGrpc++
			case "no_grpc_tls":
				s.NoGrpcTLS++
			case "insecure_grpc_reflection":
				s.InsecureGrpcReflection++
			case "missing_grpc_auth":
				s.MissingGrpcAuth++
			case "grpc_health_no_auth":
				s.GrpcHealthNoAuth++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gRPC Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Plaintext gRPC:              %d\n", r.Summary.PlaintextGrpc)
	fmt.Fprintf(&b, "  Missing gRPC TLS:            %d\n", r.Summary.NoGrpcTLS)
	fmt.Fprintf(&b, "  Insecure reflection:         %d\n", r.Summary.InsecureGrpcReflection)
	fmt.Fprintf(&b, "  Missing gRPC auth:           %d\n", r.Summary.MissingGrpcAuth)
	fmt.Fprintf(&b, "  Health check no auth:        %d\n\n", r.Summary.GrpcHealthNoAuth)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
