package tlsconfig

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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	WeakProtocol      int `json:"weak_protocol"`
	WeakCipher        int `json:"weak_cipher"`
	SelfSignedCert    int `json:"self_signed_cert"`
	MissingCertVerify int `json:"missing_cert_verify"`
	ExpiredCert       int `json:"expired_cert"`
	InsecureRedirect  int `json:"insecure_redirect"`
}

var weakProtocols = []string{
	"sslv2", "sslv3", "ssl_protocols sslv",
	"tlsv1.0", "tlsv1 ", "tls1.0",
	"tlsv1.1", "tls1.1",
	"min_protocol_version=tls1.0",
	"min_protocol_version=ssl",
}

var weakCiphers = []string{
	"rc4", "des-cbc", "3des",
	"null-sha", "null-md5",
	"export-", "anon-",
	"weak_cipher", "cipher_suite=null",
	"ssl_ciphers null", "ssl_ciphers low",
}

var selfSignedPatterns = []string{
	"self_signed", "self-signed",
	"generate_self_signed", "selfsigned",
	"allow_self_signed=true",
	"verify_client off",
}

var noVerifyPatterns = []string{
	"ssl_verify=false", "ssl_verify off",
	"tls_verify=false", "tls_skip_verify",
	"insecureskipverify=true", "insecure_skip_verify",
	"verify_ssl=false", "verify_certs=false",
	"node_tls_reject_unauthorized=0",
}

var expiredPatterns = []string{
	"expired_cert", "cert_expired",
	"ignore_expir", "allow_expired",
	"skip_cert_date", "ignore_cert_error",
}

var insecureRedirectPatterns = []string{
	"redirect http://", "redirect_to=http://",
	"force_ssl=false", "https_redirect=false",
	"hsts=false", "strict_transport=false",
	"x-forwarded-proto http",
}

func gatherText(svc compose.Service) string {
	var parts []string
	parts = append(parts, svc.Entrypoint...)
	parts = append(parts, svc.Command...)
	parts = append(parts, svc.Environment...)
	for _, v := range svc.Labels {
		parts = append(parts, v)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func containsAny(text string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}
	text := gatherText(svc)

	if containsAny(text, weakProtocols) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "tls_weak_protocol",
			Message: fmt.Sprintf("Service %q uses a weak or deprecated TLS/SSL protocol version", svc.Name),
		})
	}

	if containsAny(text, weakCiphers) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "tls_weak_cipher",
			Message: fmt.Sprintf("Service %q configures weak or null cipher suites", svc.Name),
		})
	}

	if containsAny(text, selfSignedPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "tls_self_signed",
			Message: fmt.Sprintf("Service %q uses or allows self-signed certificates", svc.Name),
		})
	}

	if containsAny(text, noVerifyPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "tls_no_verify",
			Message: fmt.Sprintf("Service %q disables certificate verification", svc.Name),
		})
	}

	if containsAny(text, expiredPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "tls_expired_cert",
			Message: fmt.Sprintf("Service %q allows or ignores expired certificates", svc.Name),
		})
	}

	if containsAny(text, insecureRedirectPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "tls_insecure_redirect",
			Message: fmt.Sprintf("Service %q redirects to or forces HTTP instead of HTTPS", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Summary.TotalServices++
			for _, f := range sr.Findings {
				r.Summary.TotalFindings++
				switch f.Rule {
				case "tls_weak_protocol":
					r.Summary.WeakProtocol++
				case "tls_weak_cipher":
					r.Summary.WeakCipher++
				case "tls_self_signed":
					r.Summary.SelfSignedCert++
				case "tls_no_verify":
					r.Summary.MissingCertVerify++
				case "tls_expired_cert":
					r.Summary.ExpiredCert++
				case "tls_insecure_redirect":
					r.Summary.InsecureRedirect++
				}
			}
			r.Services = append(r.Services, sr)
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TLS Configuration Audit (%s)\n", r.Path)
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	if r.Summary.TotalFindings == 0 {
		b.WriteString("  All services: no findings.\n")
		return b.String()
	}

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
