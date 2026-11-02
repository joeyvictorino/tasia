package logsecrets

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
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
	SecretsInOptions  int `json:"secrets_in_options"`
	SecretsInURLs     int `json:"secrets_in_urls"`
	InsecureTransport int `json:"insecure_transport"`
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key|apikey|api-key)\s*=\s*\S+`),
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key|apikey|api-key)\s*:\s*\S+`),
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_.]+`),
	regexp.MustCompile(`(?i)(aws_secret_access_key|aws_access_key_id)\s*=\s*\S+`),
}

var urlSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`://[^:]+:[^@]+@`),
	regexp.MustCompile(`(?i)token=[a-zA-Z0-9\-_.]+`),
	regexp.MustCompile(`(?i)api_key=[a-zA-Z0-9\-_.]+`),
}

var sensitiveOptionKeys = map[string]bool{
	"splunk-token":        true,
	"splunk-source":       false,
	"gelf-compression-type": false,
	"fluentd-address":     false,
	"syslog-address":      false,
	"awslogs-credentials-endpoint": true,
}

func isInsecureURL(val string) bool {
	lower := strings.ToLower(val)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "tcp://") ||
		strings.HasPrefix(lower, "udp://")
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := ServiceResult{Service: svc.Name, File: cf.Path}
			if svc.Logging == nil {
				r.Services = append(r.Services, sr)
				continue
			}
			for key, val := range svc.Logging.Options {
				if sensitiveOptionKeys[key] {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "log_secret_in_option",
						Message: fmt.Sprintf("Service '%s' has sensitive logging option '%s' with embedded credential", svc.Name, key),
					})
				}

				for _, pat := range secretPatterns {
					if pat.MatchString(val) {
						sr.Findings = append(sr.Findings, Finding{
							Level:   "high",
							Rule:    "log_secret_in_option",
							Message: fmt.Sprintf("Service '%s' logging option '%s' contains credential pattern", svc.Name, key),
						})
						break
					}
				}

				for _, pat := range urlSecretPatterns {
					if pat.MatchString(val) {
						sr.Findings = append(sr.Findings, Finding{
							Level:   "high",
							Rule:    "log_secret_in_url",
							Message: fmt.Sprintf("Service '%s' logging option '%s' contains credentials in URL", svc.Name, key),
						})
						break
					}
				}

				if isInsecureURL(val) {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "medium",
						Rule:    "log_insecure_transport",
						Message: fmt.Sprintf("Service '%s' logging option '%s' uses insecure transport (%s)", svc.Name, key, strings.SplitN(val, "://", 2)[0]),
					})
				}
			}
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
			case "log_secret_in_option":
				s.SecretsInOptions++
			case "log_secret_in_url":
				s.SecretsInURLs++
			case "log_insecure_transport":
				s.InsecureTransport++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Log Secret Detection (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Secrets in options: %d\n", r.Summary.SecretsInOptions)
	fmt.Fprintf(&b, "  Secrets in URLs:    %d\n", r.Summary.SecretsInURLs)
	fmt.Fprintf(&b, "  Insecure transport: %d\n\n", r.Summary.InsecureTransport)
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
