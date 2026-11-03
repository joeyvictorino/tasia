package sshaudit

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

var ruleRootLogin = ruleInfo{ID: "SSH-001"}
var rulePasswordAuth = ruleInfo{ID: "SSH-002"}
var ruleDefaultPort = ruleInfo{ID: "SSH-003"}
var ruleNoHostKeys = ruleInfo{ID: "SSH-004"}
var ruleX11Forwarding = ruleInfo{ID: "SSH-005"}
var ruleEmptyPasswords = ruleInfo{ID: "SSH-006"}

func isSSHService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "ssh") || strings.Contains(combined, "openssh") || strings.Contains(combined, "dropbear") || strings.Contains(combined, "sshd")
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

func hasTargetPort22(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 22 {
			return true
		}
		parts := strings.Split(p.Raw, ":")
		last := parts[len(parts)-1]
		if last == "22" {
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

	if !isSSHService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "PERMIT_ROOT_LOGIN", "SSH_ROOT_LOGIN", "ROOT_LOGIN"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleRootLogin.ID,
				Detail:  fmt.Sprintf("root login enabled (%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "PASSWORD_AUTH", "SSH_PASSWORD_AUTH", "PASSWORD_AUTHENTICATION"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    rulePasswordAuth.ID,
				Detail:  "password authentication enabled (prefer key-based auth)",
			})
		}
	}

	if hasTargetPort22(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleDefaultPort.ID,
			Detail:  "SSH exposed on default port 22",
		})
	}

	if !hasVolumePath(svc, "host_key") && !hasVolumePath(svc, "ssh_host") && !envExists(svc, "SSH_HOST_KEY", "HOST_KEY_FILE") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoHostKeys.ID,
			Detail:  "no host key volume or environment variable (ephemeral keys on restart)",
		})
	}

	if v, ok := envVal(svc, "X11_FORWARDING", "SSH_X11_FORWARDING", "X11FORWARDING"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleX11Forwarding.ID,
				Detail:  "X11 forwarding enabled (increases attack surface)",
			})
		}
	}

	if v, ok := envVal(svc, "PERMIT_EMPTY_PASSWORDS", "SSH_EMPTY_PASSWORDS", "EMPTY_PASSWORDS"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleEmptyPasswords.ID,
				Detail:  "empty passwords permitted",
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
	b.WriteString("SSH Server Security Audit\n")
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
