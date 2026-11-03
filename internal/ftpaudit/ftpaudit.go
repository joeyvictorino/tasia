package ftpaudit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service string
	Rule    string
	Detail  string
}

type ServiceResult struct {
	Service  string
	Findings []Finding
}

type Summary struct {
	TotalServices    int
	TotalFindings    int
	AffectedServices int
	ByRule           map[string]int
}

type Report struct {
	Results []ServiceResult
	Summary Summary
}

type ruleInfo struct{ ID string }

var ruleAnonymousAccess = ruleInfo{ID: "FTP-001"}
var ruleNoTLS = ruleInfo{ID: "FTP-002"}
var ruleDefaultPort = ruleInfo{ID: "FTP-003"}
var ruleWriteEnabled = ruleInfo{ID: "FTP-004"}
var ruleWeakAuth = ruleInfo{ID: "FTP-005"}
var rulePassiveMode = ruleInfo{ID: "FTP-006"}

func isFTPService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "ftp") || strings.Contains(combined, "vsftpd") ||
		strings.Contains(combined, "proftpd") || strings.Contains(combined, "pure-ftpd") ||
		strings.Contains(combined, "filezilla")
}

func envVal(svc compose.Service, keys ...string) (string, bool) {
	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(parts[0]))
		for _, key := range keys {
			if k == key {
				return strings.TrimSpace(parts[1]), true
			}
		}
	}
	return "", false
}

func isTruthy(v string) bool {
	low := strings.ToLower(v)
	return low == "true" || low == "1" || low == "yes"
}

func isFalsy(v string) bool {
	low := strings.ToLower(v)
	return low == "false" || low == "0" || low == "no" || low == "disabled"
}

func hasFTPPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 21 || p.TargetPort == 20 {
			return true
		}
		parts := strings.Split(p.Raw, ":")
		last := parts[len(parts)-1]
		if last == "21" || last == "20" {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	if !isFTPService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "ANONYMOUS_ENABLE", "FTP_ANONYMOUS", "ALLOW_ANONYMOUS", "ANONYMOUS_ACCESS"); ok {
		if isTruthy(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleAnonymousAccess.ID,
				Detail:  fmt.Sprintf("anonymous FTP access enabled (%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "SSL_ENABLE", "FTP_TLS", "TLS_ENABLE", "FTPS_ENABLE", "FTP_SSL"); ok {
		if isFalsy(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNoTLS.ID,
				Detail:  "FTP TLS/SSL disabled (credentials transmitted in plaintext)",
			})
		}
	}

	if hasFTPPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleDefaultPort.ID,
			Detail:  "FTP exposed on default ports (20/21)",
		})
	}

	if v, ok := envVal(svc, "WRITE_ENABLE", "FTP_WRITE", "ALLOW_UPLOAD", "ANON_UPLOAD_ENABLE"); ok {
		if isTruthy(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWriteEnabled.ID,
				Detail:  "FTP write/upload access enabled",
			})
		}
	}

	if v, ok := envVal(svc, "FTP_USER", "FTP_USERNAME"); ok {
		low := strings.ToLower(v)
		if low == "admin" || low == "ftp" || low == "user" || low == "root" || low == "anonymous" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWeakAuth.ID,
				Detail:  fmt.Sprintf("weak/default FTP username (%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "PASV_MIN_PORT", "PASSIVE_MIN_PORT"); ok {
		if v != "" {
			if _, ok2 := envVal(svc, "PASV_MAX_PORT", "PASSIVE_MAX_PORT"); ok2 {
				sr.Findings = append(sr.Findings, Finding{
					Service: svc.Name,
					Rule:    rulePassiveMode.ID,
					Detail:  "FTP passive mode port range exposed (wide port range increases attack surface)",
				})
			}
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	var results []ServiceResult
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc)
			results = append(results, sr)
		}
	}
	return Report{Results: results, Summary: summarize(results)}
}

func summarize(results []ServiceResult) Summary {
	s := Summary{ByRule: map[string]int{}}
	s.TotalServices = len(results)
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.AffectedServices++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			s.ByRule[f.Rule]++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("FTP Server Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Services affected:  %d\n", r.Summary.AffectedServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)
	for _, sr := range r.Results {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s\n", sr.Service)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Rule, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
