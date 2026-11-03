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

type ruleInfo struct {
	ID string
}

var ruleAnonymousLogin = ruleInfo{ID: "FTP-001"}
var rulePlaintextPort = ruleInfo{ID: "FTP-002"}
var ruleNoTLS = ruleInfo{ID: "FTP-003"}
var ruleWritableAnonymous = ruleInfo{ID: "FTP-004"}
var rulePassivePortRange = ruleInfo{ID: "FTP-005"}
var ruleDefaultCredentials = ruleInfo{ID: "FTP-006"}

func isFTPService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "ftp") || strings.Contains(combined, "vsftpd") || strings.Contains(combined, "proftpd") || strings.Contains(combined, "pure-ftpd")
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

func envExists(svc compose.Service, keys ...string) bool {
	_, found := envVal(svc, keys...)
	return found
}

func hasPort(svc compose.Service, port string) bool {
	for _, p := range svc.Ports {
		if strings.Contains(p.Raw, port) {
			return true
		}
	}
	return false
}

func hasVolumePath(svc compose.Service, needle string) bool {
	for _, v := range svc.Volumes {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name}

	if !isFTPService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "FTP_ANONYMOUS", "ANONYMOUS_ENABLE", "ALLOW_ANONYMOUS"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleAnonymousLogin.ID,
				Detail:  fmt.Sprintf("anonymous FTP login enabled (%s)", v),
			})
		}
	}

	if hasPort(svc, "21") && !hasPort(svc, "990") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    rulePlaintextPort.ID,
			Detail:  "FTP port 21 exposed without implicit FTPS port 990",
		})
	}

	if !envExists(svc, "FTP_TLS", "SSL_ENABLE", "TLS_CERT", "FTP_SSL", "FTPS_ENABLE") && !hasVolumePath(svc, "tls") && !hasVolumePath(svc, "ssl") && !hasVolumePath(svc, "cert") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoTLS.ID,
			Detail:  "no TLS/SSL configuration detected for FTP service",
		})
	}

	if v, ok := envVal(svc, "ANON_UPLOAD_ENABLE", "FTP_ANON_WRITE", "ANONYMOUS_WRITE"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWritableAnonymous.ID,
				Detail:  "anonymous users can upload files",
			})
		}
	}

	if hasPort(svc, "21") && !envExists(svc, "PASV_MIN_PORT", "PASSIVE_PORT_RANGE", "FTP_PASSIVE_PORTS") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    rulePassivePortRange.ID,
			Detail:  "no passive port range configured (may expose random ports)",
		})
	}

	imgLower := strings.ToLower(svc.Image)
	if strings.Contains(imgLower, "vsftpd") || strings.Contains(imgLower, "proftpd") || strings.Contains(imgLower, "pure-ftpd") || strings.Contains(imgLower, "ftp") {
		hasAuth := envExists(svc, "FTP_USER", "FTP_PASSWORD", "FTP_USERS", "USER_FILE") || hasVolumePath(svc, "passwd") || hasVolumePath(svc, "user")
		if !hasAuth {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleDefaultCredentials.ID,
				Detail:  "FTP server without explicit user/password configuration",
			})
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	var results []ServiceResult
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
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
