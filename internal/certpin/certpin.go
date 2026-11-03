package certpin

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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	TLSVerifyDisabled    int `json:"tls_verify_disabled"`
	SelfSignedAllowed    int `json:"self_signed_allowed"`
	MissingCertPin       int `json:"missing_cert_pin"`
	InsecureProtocol     int `json:"insecure_protocol"`
	ExpiredCertRisk      int `json:"expired_cert_risk"`
}

var tlsDisablePatterns = []string{
	"SSL_VERIFY=FALSE", "SSL_VERIFY=0",
	"TLS_VERIFY=FALSE", "TLS_VERIFY=0",
	"VERIFY_SSL=FALSE", "VERIFY_SSL=0",
	"NODE_TLS_REJECT_UNAUTHORIZED=0",
	"PYTHONHTTPSVERIFY=0",
	"GIT_SSL_NO_VERIFY=1", "GIT_SSL_NO_VERIFY=TRUE",
	"CURL_SSL_VERIFY=FALSE",
	"REQUESTS_CA_BUNDLE=",
	"SSL_CERT_FILE=/DEV/NULL",
	"VERIFY_CERTS=FALSE", "VERIFY_CERTS=0",
}

var selfSignedPatterns = []string{
	"SELF_SIGNED=TRUE", "SELF_SIGNED=1",
	"ALLOW_SELF_SIGNED=TRUE", "ALLOW_SELF_SIGNED=1",
	"ACCEPT_SELF_SIGNED=TRUE",
	"SSL_ALLOW_SELF_SIGNED=TRUE",
	"TLS_INSECURE=TRUE", "TLS_INSECURE=1",
	"INSECURE_TLS=TRUE", "INSECURE_TLS=1",
}

var insecureProtocolPatterns = []string{
	"HTTP://", "FTP://", "MQTT://", "AMQP://",
}

var certPinIndicators = []string{
	"CERT_PIN", "CERTIFICATE_PIN", "TLS_PIN",
	"CA_BUNDLE", "CA_CERT", "CA_FILE",
	"SSL_CA_CERTS", "SSL_CERTFILE",
	"TRUSTED_CA", "ROOT_CA",
}

var sensitiveConnections = []string{
	"postgres", "mysql", "redis", "mongo", "elasticsearch",
	"rabbitmq", "kafka", "vault", "consul", "etcd",
	"openai", "anthropic", "huggingface",
}

func isSensitiveConnection(name, image string) bool {
	lower := strings.ToLower(name + " " + image)
	for _, s := range sensitiveConnections {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func hasCertPinning(envVars []string) bool {
	for _, e := range envVars {
		upper := strings.ToUpper(e)
		for _, pat := range certPinIndicators {
			if strings.Contains(upper, pat) {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 && len(strings.TrimSpace(parts[1])) > 0 {
					return true
				}
			}
		}
	}
	return false
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	sensitive := isSensitiveConnection(svc.Name, svc.Image)

	for _, e := range svc.Environment {
		upper := strings.ToUpper(e)

		for _, pat := range tlsDisablePatterns {
			if strings.Contains(upper, pat) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "certpin_tls_disabled",
					Message: fmt.Sprintf("Service '%s' disables TLS verification via '%s'; connections are vulnerable to MITM attacks", svc.Name, strings.SplitN(e, "=", 2)[0]),
				})
				break
			}
		}

		for _, pat := range selfSignedPatterns {
			if strings.Contains(upper, pat) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "certpin_self_signed",
					Message: fmt.Sprintf("Service '%s' allows self-signed certificates via '%s'; use a proper CA for production", svc.Name, strings.SplitN(e, "=", 2)[0]),
				})
				break
			}
		}

		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			val := strings.ToUpper(parts[1])
			for _, proto := range insecureProtocolPatterns {
				if strings.Contains(val, proto) && sensitive {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "certpin_insecure_proto",
						Message: fmt.Sprintf("Service '%s' uses insecure protocol in '%s' (%s); upgrade to TLS-encrypted transport", svc.Name, parts[0], strings.TrimRight(proto, "://")),
					})
					break
				}
			}
		}
	}

	if sensitive && !hasCertPinning(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "certpin_missing",
			Message: fmt.Sprintf("Service '%s' (sensitive) has no certificate pinning or CA bundle configured; consider adding CA_CERT or SSL_CA_CERTS", svc.Name),
		})
	}

	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := parts[1]
		if (strings.Contains(key, "CERT") || strings.Contains(key, "SSL") || strings.Contains(key, "TLS")) &&
			strings.Contains(val, "expire") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "certpin_expired_risk",
				Message: fmt.Sprintf("Service '%s' references certificate expiry in '%s'; ensure automated certificate renewal is configured", svc.Name, parts[0]),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "certpin_tls_disabled":
				s.TLSVerifyDisabled++
			case "certpin_self_signed":
				s.SelfSignedAllowed++
			case "certpin_missing":
				s.MissingCertPin++
			case "certpin_insecure_proto":
				s.InsecureProtocol++
			case "certpin_expired_risk":
				s.ExpiredCertRisk++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Certificate Pinning & TLS Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  TLS verify disabled:     %d\n", r.Summary.TLSVerifyDisabled)
	fmt.Fprintf(&b, "  Self-signed allowed:     %d\n", r.Summary.SelfSignedAllowed)
	fmt.Fprintf(&b, "  Missing cert pinning:    %d\n", r.Summary.MissingCertPin)
	fmt.Fprintf(&b, "  Insecure protocols:      %d\n", r.Summary.InsecureProtocol)
	fmt.Fprintf(&b, "  Expired cert risk:       %d\n\n", r.Summary.ExpiredCertRisk)
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
