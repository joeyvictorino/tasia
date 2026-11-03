package vpnaudit

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

var ruleWeakCipher = ruleInfo{ID: "VPN-001"}
var ruleNoAuth = ruleInfo{ID: "VPN-002"}
var ruleDefaultPort = ruleInfo{ID: "VPN-003"}
var ruleNoTLS = ruleInfo{ID: "VPN-004"}
var rulePrivileged = ruleInfo{ID: "VPN-005"}
var ruleNoKeyVolume = ruleInfo{ID: "VPN-006"}

func isVPNService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "openvpn") || strings.Contains(combined, "wireguard") ||
		strings.Contains(combined, "strongswan") || strings.Contains(combined, "ipsec") ||
		strings.Contains(combined, "vpn-server") || strings.Contains(combined, "softether")
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

func hasVPNPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 1194 || p.TargetPort == 51820 || p.TargetPort == 500 || p.TargetPort == 4500 {
			return true
		}
		parts := strings.Split(p.Raw, ":")
		last := parts[len(parts)-1]
		cleaned := strings.Split(last, "/")[0]
		if cleaned == "1194" || cleaned == "51820" || cleaned == "500" || cleaned == "4500" {
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

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	if !isVPNService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "VPN_CIPHER", "CIPHER", "OPENVPN_CIPHER"); ok {
		low := strings.ToLower(v)
		if strings.Contains(low, "des") || strings.Contains(low, "rc4") ||
			strings.Contains(low, "blowfish") || low == "none" || low == "bf-cbc" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWeakCipher.ID,
				Detail:  fmt.Sprintf("weak cipher configured (%s)", v),
			})
		}
	}

	if v, ok := envVal(svc, "VPN_AUTH", "AUTH_MODE", "OPENVPN_AUTH"); ok {
		low := strings.ToLower(v)
		if low == "none" || low == "noauth" || low == "disabled" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNoAuth.ID,
				Detail:  "VPN authentication disabled",
			})
		}
	}

	if hasVPNPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleDefaultPort.ID,
			Detail:  "VPN exposed on default port",
		})
	}

	if v, ok := envVal(svc, "TLS_AUTH", "TLS_CRYPT", "OPENVPN_TLS"); ok {
		low := strings.ToLower(v)
		if low == "false" || low == "0" || low == "no" || low == "disabled" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleNoTLS.ID,
				Detail:  "TLS authentication disabled (HMAC firewall bypassed)",
			})
		}
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    rulePrivileged.ID,
			Detail:  "VPN container running in privileged mode",
		})
	}

	if !hasVolumePath(svc, "key") && !hasVolumePath(svc, "cert") && !hasVolumePath(svc, "pki") &&
		!hasVolumePath(svc, "private") && !hasVolumePath(svc, "wg0.conf") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoKeyVolume.ID,
			Detail:  "no key/certificate volume mounted (ephemeral keys on restart)",
		})
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
	b.WriteString("VPN Server Security Audit\n")
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
