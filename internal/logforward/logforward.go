package logforward

import (
	"fmt"
	"regexp"
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
	InsecureSyslog       int `json:"insecure_syslog"`
	ExposedToken         int `json:"exposed_token"`
	NoTLS                int `json:"no_tls"`
	SplunkNoSSL          int `json:"splunk_no_ssl"`
	FluentdInsecure      int `json:"fluentd_insecure"`
	NoLoggingConfig      int `json:"no_logging_config"`
}

var tokenRe = regexp.MustCompile(`(?i)(token|api[_-]?key|secret|password|auth)`)

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

	if svc.Logging == nil {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "logforward_no_config",
			Message: fmt.Sprintf("Service '%s' has no logging configuration; logs may be lost or unforwarded", svc.Name),
		})
		return sr
	}

	driver := strings.ToLower(svc.Logging.Driver)
	opts := svc.Logging.Options

	if driver == "syslog" {
		addr := opts["syslog-address"]
		if addr == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "logforward_insecure_syslog",
				Message: fmt.Sprintf("Service '%s' uses syslog driver without syslog-address; logs go to local syslog only", svc.Name),
			})
		} else if !strings.HasPrefix(addr, "tcp+tls://") && !strings.HasPrefix(addr, "tls://") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "logforward_no_tls",
				Message: fmt.Sprintf("Service '%s' forwards syslog to '%s' without TLS; log data transmitted in cleartext", svc.Name, addr),
			})
		}
	}

	if driver == "splunk" {
		if v, ok := opts["splunk-verify-connection"]; ok && (v == "false" || v == "0") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "logforward_splunk_no_ssl",
				Message: fmt.Sprintf("Service '%s' disables Splunk TLS verification; vulnerable to MITM on log transport", svc.Name),
			})
		}
		if v, ok := opts["splunk-insecureskipverify"]; ok && (v == "true" || v == "1") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "logforward_splunk_no_ssl",
				Message: fmt.Sprintf("Service '%s' skips Splunk TLS certificate verification; log data may be intercepted", svc.Name),
			})
		}
	}

	if driver == "fluentd" {
		if v, ok := opts["fluentd-sub-second-precision"]; ok && v != "" {
			_ = v
		}
		addr := opts["fluentd-address"]
		if addr != "" && !strings.Contains(addr, "tls") && !strings.Contains(addr, "ssl") {
			for k := range opts {
				if strings.Contains(strings.ToLower(k), "tls") || strings.Contains(strings.ToLower(k), "ssl") {
					goto fluentdTLSFound
				}
			}
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "logforward_fluentd_insecure",
				Message: fmt.Sprintf("Service '%s' forwards to fluentd at '%s' without apparent TLS configuration", svc.Name, addr),
			})
		fluentdTLSFound:
		}
	}

	if driver == "gelf" {
		addr := opts["gelf-address"]
		if addr != "" && strings.HasPrefix(addr, "udp://") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "logforward_no_tls",
				Message: fmt.Sprintf("Service '%s' uses GELF over UDP to '%s'; logs may be lost or intercepted", svc.Name, addr),
			})
		}
	}

	for k, v := range opts {
		if tokenRe.MatchString(k) && v != "" && !strings.HasPrefix(v, "${") && !strings.HasPrefix(v, "$") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "logforward_exposed_token",
				Message: fmt.Sprintf("Service '%s' has hardcoded credential in logging option '%s'; use environment variable reference", svc.Name, k),
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
			case "logforward_insecure_syslog":
				s.InsecureSyslog++
			case "logforward_exposed_token":
				s.ExposedToken++
			case "logforward_no_tls":
				s.NoTLS++
			case "logforward_splunk_no_ssl":
				s.SplunkNoSSL++
			case "logforward_fluentd_insecure":
				s.FluentdInsecure++
			case "logforward_no_config":
				s.NoLoggingConfig++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Log Forwarding Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Insecure syslog:       %d\n", r.Summary.InsecureSyslog)
	fmt.Fprintf(&b, "  Exposed tokens:        %d\n", r.Summary.ExposedToken)
	fmt.Fprintf(&b, "  No TLS:                %d\n", r.Summary.NoTLS)
	fmt.Fprintf(&b, "  Splunk no SSL:         %d\n", r.Summary.SplunkNoSSL)
	fmt.Fprintf(&b, "  Fluentd insecure:      %d\n", r.Summary.FluentdInsecure)
	fmt.Fprintf(&b, "  No logging config:     %d\n\n", r.Summary.NoLoggingConfig)
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
