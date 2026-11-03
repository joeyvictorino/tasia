package snmpaudit

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

var ruleDefaultCommunity = ruleInfo{ID: "SNMP-001"}
var ruleSNMPv1v2 = ruleInfo{ID: "SNMP-002"}
var ruleDefaultPort = ruleInfo{ID: "SNMP-003"}
var ruleWriteAccess = ruleInfo{ID: "SNMP-004"}
var ruleNoAuth = ruleInfo{ID: "SNMP-005"}
var ruleNoEncryption = ruleInfo{ID: "SNMP-006"}

var defaultCommunities = []string{
	"public", "private", "community", "default", "snmp",
	"monitor", "manager", "admin", "test", "read", "write",
}

func isSNMPService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	return strings.Contains(combined, "snmp") || strings.Contains(combined, "net-snmp") ||
		strings.Contains(combined, "snmpd") || strings.Contains(combined, "snmpsim")
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

func hasSNMPPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 161 || p.TargetPort == 162 {
			return true
		}
		parts := strings.Split(p.Raw, ":")
		last := parts[len(parts)-1]
		if last == "161" || last == "162" || last == "161/udp" || last == "162/udp" {
			return true
		}
	}
	return false
}

func isDefaultCommunity(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	for _, dc := range defaultCommunities {
		if low == dc {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	if !isSNMPService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "SNMP_COMMUNITY", "COMMUNITY_STRING", "SNMP_COMMUNITY_STRING", "READ_COMMUNITY"); ok {
		if isDefaultCommunity(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleDefaultCommunity.ID,
				Detail:  fmt.Sprintf("default community string in use (%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "SNMP_VERSION", "SNMP_PROTOCOL_VERSION"); ok {
		low := strings.ToLower(v)
		if low == "1" || low == "2" || low == "2c" || low == "v1" || low == "v2" || low == "v2c" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleSNMPv1v2.ID,
				Detail:  fmt.Sprintf("SNMPv1/v2c in use (no encryption, community-based auth) version=%s", v),
			})
		}
	}

	if hasSNMPPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleDefaultPort.ID,
			Detail:  "SNMP exposed on default ports (161/162)",
		})
	}

	if v, ok := envVal(svc, "WRITE_COMMUNITY", "SNMP_WRITE_COMMUNITY", "RW_COMMUNITY"); ok {
		if v != "" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWriteAccess.ID,
				Detail:  "SNMP write access enabled (configuration change risk)",
			})
		}
	}

	if v, ok := envVal(svc, "SNMP_AUTH", "AUTH_PROTOCOL", "SNMP_AUTH_PROTOCOL"); ok {
		low := strings.ToLower(v)
		if low == "none" || low == "noauth" || low == "disabled" || low == "false" || low == "0" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNoAuth.ID,
				Detail:  "SNMP authentication disabled",
			})
		}
	}

	if v, ok := envVal(svc, "SNMP_PRIV", "PRIV_PROTOCOL", "SNMP_PRIV_PROTOCOL", "SNMP_ENCRYPT"); ok {
		low := strings.ToLower(v)
		if low == "none" || low == "nopriv" || low == "disabled" || low == "false" || low == "0" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNoEncryption.ID,
				Detail:  "SNMP privacy/encryption disabled (traffic visible in plaintext)",
			})
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
	b.WriteString("SNMP Security Audit\n")
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
