package jwtsec

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	WeakJWTAlgorithm    int `json:"weak_jwt_algorithm"`
	NoJWTExpiry         int `json:"no_jwt_expiry"`
	HardcodedJWTSecret  int `json:"hardcoded_jwt_secret"`
	InsecureJWTAudience int `json:"insecure_jwt_audience"`
	NoJWTIssuerCheck    int `json:"no_jwt_issuer_check"`
}

var jwtEnvKeys = []string{
	"jwt_secret", "jwt_key", "jwt_signing_key",
	"jwt_private_key", "jwt_public_key", "jwt_token",
	"jwt_issuer", "jwt_audience", "jwt_algorithm",
	"jwt_expiry", "jwt_expires", "jwt_ttl",
	"auth_jwt", "token_secret", "jwt_secret_key",
}

var weakAlgorithms = []string{
	"none", "hs256", "hs384", "hs512",
}

var strongAlgorithms = []string{
	"rs256", "rs384", "rs512", "es256", "es384", "es512",
	"ps256", "ps384", "ps512", "eddsa",
}

var shortSecretPatterns = []string{
	"secret", "password", "changeme", "test",
	"key123", "mysecret", "default", "abc123",
	"jwt_secret", "tokensecret", "123456",
}

func isJWTService(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		for _, k := range jwtEnvKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func getAlgorithm(svc compose.Service) string {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "jwt_algorithm") || strings.Contains(lower, "jwt_alg") {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(strings.ToLower(parts[1]))
			}
		}
	}
	return ""
}

func hasWeakAlgorithm(svc compose.Service) bool {
	alg := getAlgorithm(svc)
	if alg == "" {
		return false
	}
	for _, weak := range weakAlgorithms {
		if alg == weak {
			return true
		}
	}
	return false
}

func hasExpiryConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "jwt_expiry") ||
			strings.Contains(lower, "jwt_expires") ||
			strings.Contains(lower, "jwt_ttl") ||
			strings.Contains(lower, "token_expiry") ||
			strings.Contains(lower, "token_ttl") ||
			strings.Contains(lower, "token_lifetime") ||
			strings.Contains(lower, "jwt_max_age") {
			return true
		}
	}
	return false
}

func hasHardcodedSecret(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if !strings.Contains(lower, "jwt_secret") && !strings.Contains(lower, "jwt_key") && !strings.Contains(lower, "jwt_signing_key") && !strings.Contains(lower, "token_secret") && !strings.Contains(lower, "jwt_secret_key") {
			continue
		}
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}
		lval := strings.ToLower(val)
		for _, p := range shortSecretPatterns {
			if lval == p {
				return true
			}
		}
		if len(val) < 16 {
			return true
		}
	}
	return false
}

func hasAudienceConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "jwt_audience") || strings.Contains(lower, "jwt_aud") {
			return true
		}
	}
	return false
}

func hasIssuerConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "jwt_issuer") || strings.Contains(lower, "jwt_iss") {
			return true
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isJWTService(svc) {
		return sr
	}

	if hasWeakAlgorithm(svc) {
		alg := getAlgorithm(svc)
		if alg == "none" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "weak_jwt_algorithm",
				Message: fmt.Sprintf("JWT service '%s' uses algorithm 'none'; this disables signature verification entirely and allows token forgery", svc.Name),
			})
		} else {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "weak_jwt_algorithm",
				Message: fmt.Sprintf("JWT service '%s' uses symmetric algorithm '%s'; asymmetric algorithms (RS256, ES256) are recommended for production to avoid shared secret distribution", svc.Name, alg),
			})
		}
	}

	if !hasExpiryConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_jwt_expiry",
			Message: fmt.Sprintf("JWT service '%s' has no token expiry configuration; tokens without expiration remain valid indefinitely if compromised", svc.Name),
		})
	}

	if hasHardcodedSecret(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "hardcoded_jwt_secret",
			Message: fmt.Sprintf("JWT service '%s' has a weak or hardcoded signing secret; use a strong randomly generated secret of at least 256 bits", svc.Name),
		})
	}

	if hasPublicPort(svc) && !hasAudienceConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "insecure_jwt_audience",
			Message: fmt.Sprintf("JWT service '%s' is publicly exposed without audience (aud) claim validation; tokens may be accepted by unintended services", svc.Name),
		})
	}

	if hasPublicPort(svc) && !hasIssuerConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "no_jwt_issuer_check",
			Message: fmt.Sprintf("JWT service '%s' is publicly exposed without issuer (iss) claim validation; tokens from other issuers may be accepted", svc.Name),
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
			case "weak_jwt_algorithm":
				s.WeakJWTAlgorithm++
			case "no_jwt_expiry":
				s.NoJWTExpiry++
			case "hardcoded_jwt_secret":
				s.HardcodedJWTSecret++
			case "insecure_jwt_audience":
				s.InsecureJWTAudience++
			case "no_jwt_issuer_check":
				s.NoJWTIssuerCheck++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "JWT Configuration Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Weak JWT algorithm:          %d\n", r.Summary.WeakJWTAlgorithm)
	fmt.Fprintf(&b, "  No JWT expiry:               %d\n", r.Summary.NoJWTExpiry)
	fmt.Fprintf(&b, "  Hardcoded JWT secret:        %d\n", r.Summary.HardcodedJWTSecret)
	fmt.Fprintf(&b, "  Insecure JWT audience:       %d\n", r.Summary.InsecureJWTAudience)
	fmt.Fprintf(&b, "  No JWT issuer check:         %d\n\n", r.Summary.NoJWTIssuerCheck)
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
