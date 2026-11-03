package smtpaudit

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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	OpenRelay          int `json:"open_relay"`
	NoSMTPTLS          int `json:"no_smtp_tls"`
	PlaintextAuth      int `json:"plaintext_auth"`
	WeakCredentials    int `json:"weak_credentials"`
	ExposedSubmission  int `json:"exposed_submission"`
}

var smtpPorts = []int{25, 465, 587, 2525}

var smtpImages = []string{
	"postfix", "mailhog", "mailpit", "mailtrap",
	"mailcatcher", "exim", "sendmail", "haraka",
	"iredmail", "modoboa", "docker-mailserver",
	"mail-server", "smtp4dev", "namshi/smtp",
}

func isSMTPService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range smtpImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "smtp") || strings.Contains(lower, "postfix") || strings.Contains(lower, "mail_server") {
			return true
		}
	}
	for _, p := range svc.Ports {
		for _, sp := range smtpPorts {
			if p.TargetPort == sp {
				return true
			}
		}
	}
	return false
}

func hasOpenRelay(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "relay_host") ||
			strings.Contains(lower, "open_relay") ||
			strings.Contains(lower, "permit_mynetworks") ||
			strings.Contains(lower, "relay_domains=*") ||
			strings.Contains(lower, "allow_relay") {
			return true
		}
	}
	return false
}

func hasSMTPTLS(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "smtp_tls") ||
			strings.Contains(lower, "smtps") ||
			strings.Contains(lower, "starttls") ||
			strings.Contains(lower, "ssl_cert") ||
			strings.Contains(lower, "tls_cert") ||
			strings.Contains(lower, "smtp_ssl") {
			return true
		}
	}
	for _, p := range svc.Ports {
		if p.TargetPort == 465 {
			return true
		}
	}
	return false
}

func hasPlaintextAuth(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if (strings.Contains(lower, "smtp_auth") || strings.Contains(lower, "sasl")) &&
			(strings.Contains(lower, "plain") || strings.Contains(lower, "login")) &&
			!strings.Contains(lower, "tls") && !strings.Contains(lower, "ssl") {
			return true
		}
	}
	return false
}

func hasWeakCredentials(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if (strings.Contains(lower, "smtp_password") || strings.Contains(lower, "smtp_pass") || strings.Contains(lower, "mail_password")) &&
			(strings.Contains(lower, "password") || strings.Contains(lower, "123") || strings.Contains(lower, "admin") || strings.Contains(lower, "test")) {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				val := strings.ToLower(strings.TrimSpace(parts[1]))
				if val == "password" || val == "admin" || val == "test" || val == "123456" || val == "smtp" || val == "mail" {
					return true
				}
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

func hasPublicSubmissionPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if (p.TargetPort == 587 || p.TargetPort == 25) && p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isSMTPService(svc) {
		return sr
	}

	if hasOpenRelay(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "open_relay",
			Message: fmt.Sprintf("SMTP service '%s' is configured as an open relay on a public port; open relays allow anyone to send email through the server and are abused for spam", svc.Name),
		})
	}

	if !hasSMTPTLS(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_smtp_tls",
			Message: fmt.Sprintf("SMTP service '%s' is publicly exposed without TLS/STARTTLS; email traffic including credentials is transmitted unencrypted", svc.Name),
		})
	}

	if hasPlaintextAuth(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "plaintext_auth",
			Message: fmt.Sprintf("SMTP service '%s' uses PLAIN/LOGIN authentication without TLS; credentials are transmitted in cleartext", svc.Name),
		})
	}

	if hasWeakCredentials(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "weak_credentials",
			Message: fmt.Sprintf("SMTP service '%s' uses weak or default credentials; change to strong passwords to prevent unauthorized mail sending", svc.Name),
		})
	}

	if hasPublicSubmissionPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "exposed_submission",
			Message: fmt.Sprintf("SMTP service '%s' exposes mail submission port publicly; restrict submission ports to authenticated users on internal networks", svc.Name),
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
			case "open_relay":
				s.OpenRelay++
			case "no_smtp_tls":
				s.NoSMTPTLS++
			case "plaintext_auth":
				s.PlaintextAuth++
			case "weak_credentials":
				s.WeakCredentials++
			case "exposed_submission":
				s.ExposedSubmission++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SMTP Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Open relay:                  %d\n", r.Summary.OpenRelay)
	fmt.Fprintf(&b, "  Missing SMTP TLS:            %d\n", r.Summary.NoSMTPTLS)
	fmt.Fprintf(&b, "  Plaintext auth:              %d\n", r.Summary.PlaintextAuth)
	fmt.Fprintf(&b, "  Weak credentials:            %d\n", r.Summary.WeakCredentials)
	fmt.Fprintf(&b, "  Exposed submission port:     %d\n\n", r.Summary.ExposedSubmission)
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
