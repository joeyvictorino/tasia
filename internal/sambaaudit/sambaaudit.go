package sambaaudit

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

var ruleGuestAccess = ruleInfo{ID: "SMB-001"}
var ruleNullSession = ruleInfo{ID: "SMB-002"}
var ruleSMBv1 = ruleInfo{ID: "SMB-003"}
var ruleNoEncryption = ruleInfo{ID: "SMB-004"}
var ruleDefaultPort = ruleInfo{ID: "SMB-005"}
var ruleWorldWritable = ruleInfo{ID: "SMB-006"}

func isSambaService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "samba") || strings.Contains(combined, "smbd") ||
		strings.Contains(combined, "cifs") || strings.Contains(combined, "dperson/samba")
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

func hasSMBPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 445 || p.TargetPort == 139 {
			return true
		}
		parts := strings.Split(p.Raw, ":")
		last := parts[len(parts)-1]
		if last == "445" || last == "139" {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	if !isSambaService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "GUEST_ACCESS", "SMB_GUEST", "MAP_TO_GUEST", "ALLOW_GUEST"); ok {
		if isTruthy(v) || strings.ToLower(v) == "bad user" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleGuestAccess.ID,
				Detail:  fmt.Sprintf("guest access enabled (%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "NULL_SESSION", "RESTRICT_ANONYMOUS", "SMB_NULL_SESSION"); ok {
		if isTruthy(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNullSession.ID,
				Detail:  "null sessions permitted (anonymous enumeration risk)",
			})
		}
	}

	if v, ok := envVal(svc, "SMB_MIN_PROTOCOL", "MIN_PROTOCOL", "SERVER_MIN_PROTOCOL"); ok {
		low := strings.ToLower(v)
		if low == "nt1" || low == "lanman1" || low == "lanman2" || low == "core" || low == "coreplus" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleSMBv1.ID,
				Detail:  fmt.Sprintf("SMBv1 or older protocol allowed (min_protocol=%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "SMB_ENCRYPT", "ENCRYPTION", "SERVER_SIGNING"); ok {
		low := strings.ToLower(v)
		if low == "false" || low == "0" || low == "no" || low == "disabled" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNoEncryption.ID,
				Detail:  "SMB encryption/signing disabled (traffic interception risk)",
			})
		}
	}

	if hasSMBPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleDefaultPort.ID,
			Detail:  "SMB exposed on default ports (445/139)",
		})
	}

	if v, ok := envVal(svc, "SHARE_WRITABLE", "WRITABLE"); ok {
		if isTruthy(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWorldWritable.ID,
				Detail:  "share configured as world-writable",
			})
		}
	} else if v, ok := envVal(svc, "READ_ONLY"); ok {
		low := strings.ToLower(v)
		if low == "false" || low == "0" || low == "no" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWorldWritable.ID,
				Detail:  "share configured as world-writable (read_only=false)",
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
	b.WriteString("Samba/SMB Security Audit\n")
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
