package snmpaudit

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
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	DefaultCommunity int `json:"default_community"`
	SNMPv1v2         int `json:"snmpv1v2"`
	ExposedPorts     int `json:"exposed_ports"`
	NoAuth           int `json:"no_auth"`
	WriteAccess      int `json:"write_access"`
	MissingACL       int `json:"missing_acl"`
}

var snmpImages = []string{
	"snmpd", "net-snmp", "polinux/snmpd", "elcolio/net-snmp",
	"maxwo/snmp-exporter", "prom/snmp-exporter",
	"snmp", "snmpsim",
}

func isSnmpImage(image string) bool {
	lower := strings.ToLower(image)
	for _, si := range snmpImages {
		if strings.Contains(lower, si) {
			return true
		}
	}
	return false
}

func hasEnvContaining(envs []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, e := range envs {
		if strings.Contains(strings.ToLower(e), lower) {
			return true
		}
	}
	return false
}

func getEnvValue(envs []string, key string) string {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

var defaultCommunityStrings = []string{
	"public", "private", "community", "default",
	"snmp", "admin", "monitor", "test",
}

func hasDefaultCommunity(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if !strings.Contains(lower, "communit") && !strings.Contains(lower, "rocommunity") && !strings.Contains(lower, "rwcommunity") {
			continue
		}
		parts := strings.SplitN(e, "=", 2)
		val := lower
		if len(parts) == 2 {
			val = strings.ToLower(parts[1])
		}
		for _, dc := range defaultCommunityStrings {
			if dc == "community" {
				if val == dc || strings.HasSuffix(val, "="+dc) {
					return true
				}
				continue
			}
			if strings.Contains(val, dc) {
				return true
			}
		}
	}
	return false
}

func isSnmpPort(port compose.PortMapping) bool {
	return port.TargetPort == 161 || port.TargetPort == 162 || port.TargetPort == 10161 || port.TargetPort == 10162
}

func hasV3Auth(envs []string) bool {
	if hasEnvContaining(envs, "SNMPV3") || hasEnvContaining(envs, "SNMP_V3") {
		return true
	}
	if hasEnvContaining(envs, "AUTH_PROTOCOL") || hasEnvContaining(envs, "PRIV_PROTOCOL") {
		return true
	}
	if hasEnvContaining(envs, "authPriv") || hasEnvContaining(envs, "authNoPriv") {
		return true
	}
	if hasEnvContaining(envs, "createUser") {
		return true
	}
	return false
}

func usesV1V2(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "snmpv1") || strings.Contains(lower, "snmp_v1") {
			return true
		}
		if strings.Contains(lower, "snmpv2") || strings.Contains(lower, "snmp_v2") || strings.Contains(lower, "v2c") {
			return true
		}
		if strings.Contains(lower, "rocommunity") || strings.Contains(lower, "rwcommunity") {
			return true
		}
	}
	return false
}

func hasWriteAccess(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "rwcommunity") || strings.Contains(lower, "write") {
			return true
		}
	}
	return false
}

func hasACL(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "agentaddress") && (strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "localhost")) {
			return true
		}
		if strings.Contains(lower, "com2sec") || strings.Contains(lower, "access") || strings.Contains(lower, "view") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isSnmpImage(svc.Image) {
		return sr
	}

	if hasDefaultCommunity(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "default_community",
			Message: fmt.Sprintf("Service '%s' uses default SNMP community string (public/private/community); change to a strong secret", svc.Name),
		})
	}

	if usesV1V2(svc.Environment) && !hasV3Auth(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "snmpv1v2",
			Message: fmt.Sprintf("Service '%s' uses SNMPv1/v2c which transmits community strings in cleartext; upgrade to SNMPv3", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isSnmpPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes SNMP port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
	}

	if !hasV3Auth(svc.Environment) && !hasDefaultCommunity(svc.Environment) {
		hasCommunity := false
		for _, e := range svc.Environment {
			lower := strings.ToLower(e)
			if strings.Contains(lower, "communit") || strings.Contains(lower, "rocommunity") || strings.Contains(lower, "rwcommunity") {
				hasCommunity = true
			}
		}
		if !hasCommunity {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "no_auth",
				Message: fmt.Sprintf("Service '%s' SNMP has no authentication configured; no community string or SNMPv3 credentials", svc.Name),
			})
		}
	}

	if hasWriteAccess(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "write_access",
			Message: fmt.Sprintf("Service '%s' SNMP grants write access (rwcommunity); restrict to read-only unless necessary", svc.Name),
		})
	}

	if !hasACL(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_acl",
			Message: fmt.Sprintf("Service '%s' SNMP has no access control (com2sec/view) configured; restrict source networks", svc.Name),
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
			case "default_community":
				s.DefaultCommunity++
			case "snmpv1v2":
				s.SNMPv1v2++
			case "exposed_port":
				s.ExposedPorts++
			case "no_auth":
				s.NoAuth++
			case "write_access":
				s.WriteAccess++
			case "missing_acl":
				s.MissingACL++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SNMP Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Default community strings: %d\n", r.Summary.DefaultCommunity)
	fmt.Fprintf(&b, "  SNMPv1/v2c usage:          %d\n", r.Summary.SNMPv1v2)
	fmt.Fprintf(&b, "  Exposed ports:             %d\n", r.Summary.ExposedPorts)
	fmt.Fprintf(&b, "  No authentication:         %d\n", r.Summary.NoAuth)
	fmt.Fprintf(&b, "  Write access:              %d\n", r.Summary.WriteAccess)
	fmt.Fprintf(&b, "  Missing ACL:               %d\n\n", r.Summary.MissingACL)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Level), f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
