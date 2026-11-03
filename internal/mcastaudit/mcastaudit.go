package mcastaudit

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
	TotalServices          int `json:"total_services"`
	TotalFindings          int `json:"total_findings"`
	UnrestrictedMulticast  int `json:"unrestricted_multicast"`
	MissingIGMPSnooping    int `json:"missing_igmp_snooping"`
	BroadcastStormRisk     int `json:"broadcast_storm_risk"`
	ExcessiveBroadcastDomain int `json:"excessive_broadcast_domain"`
	MulticastCapability    int `json:"multicast_capability"`
}

var multicastSysctls = []string{
	"net.ipv4.igmp_max_memberships",
	"net.ipv4.igmp_max_msf",
	"net.ipv4.conf.all.mc_forwarding",
	"net.ipv4.conf.default.mc_forwarding",
	"net.ipv6.conf.all.mc_forwarding",
	"net.ipv6.conf.default.mc_forwarding",
}

func isMulticastSysctl(key string) bool {
	lower := strings.ToLower(key)
	for _, ms := range multicastSysctls {
		if lower == ms {
			return true
		}
	}
	return strings.Contains(lower, "igmp") || strings.Contains(lower, "mc_forwarding") || strings.Contains(lower, "multicast")
}

func allowsMulticast(svc compose.Service) bool {
	mode := strings.TrimSpace(strings.ToLower(svc.NetworkMode))
	return mode == "" || mode == "bridge" || mode == "default" || mode == "host"
}

func analyzeService(svc compose.Service, file string, bridgePeerCount int) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !allowsMulticast(svc) {
		return sr
	}

	for _, c := range svc.CapAdd {
		upper := strings.ToUpper(c)
		if upper == "NET_ADMIN" || upper == "NET_RAW" || upper == "ALL" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "unrestricted_multicast",
				Message: fmt.Sprintf("Service '%s' has %s capability; this allows sending arbitrary multicast/broadcast traffic and joining multicast groups", svc.Name, upper),
			})
			break
		}
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "unrestricted_multicast",
			Message: fmt.Sprintf("Service '%s' is privileged; it has full multicast/broadcast capability including IGMP manipulation", svc.Name),
		})
	}

	for key, val := range svc.Sysctls {
		if isMulticastSysctl(key) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "missing_igmp_snooping",
				Message: fmt.Sprintf("Service '%s' sets multicast sysctl '%s=%s'; custom multicast settings may bypass IGMP snooping controls", svc.Name, key, val),
			})
		}
	}

	mode := strings.TrimSpace(strings.ToLower(svc.NetworkMode))
	if mode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "excessive_broadcast_domain",
			Message: fmt.Sprintf("Service '%s' uses host network mode; it shares the host's full broadcast domain and can receive all multicast/broadcast traffic", svc.Name),
		})
	}

	if bridgePeerCount > 5 && allowsMulticast(svc) && mode != "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "broadcast_storm_risk",
			Message: fmt.Sprintf("Service '%s' is on a bridge with %d services; large broadcast domains increase the risk of broadcast storms and traffic amplification", svc.Name, bridgePeerCount),
		})
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			lower := strings.ToLower(parts[1])
			if strings.Contains(lower, "multicast") || strings.Contains(lower, "broadcast") || strings.Contains(lower, "239.") || strings.Contains(lower, "224.") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "multicast_capability",
					Message: fmt.Sprintf("Service '%s' env var '%s' references multicast/broadcast address or keyword '%s'", svc.Name, parts[0], parts[1]),
				})
			}
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		bridgeCount := 0
		for _, svc := range cf.Services {
			if allowsMulticast(svc) {
				mode := strings.TrimSpace(strings.ToLower(svc.NetworkMode))
				if mode != "host" {
					bridgeCount++
				}
			}
		}
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, bridgeCount)
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
			case "unrestricted_multicast":
				s.UnrestrictedMulticast++
			case "missing_igmp_snooping":
				s.MissingIGMPSnooping++
			case "broadcast_storm_risk":
				s.BroadcastStormRisk++
			case "excessive_broadcast_domain":
				s.ExcessiveBroadcastDomain++
			case "multicast_capability":
				s.MulticastCapability++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Multicast/Broadcast Network Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unrestricted multicast:       %d\n", r.Summary.UnrestrictedMulticast)
	fmt.Fprintf(&b, "  Missing IGMP snooping:        %d\n", r.Summary.MissingIGMPSnooping)
	fmt.Fprintf(&b, "  Broadcast storm risk:          %d\n", r.Summary.BroadcastStormRisk)
	fmt.Fprintf(&b, "  Excessive broadcast domain:    %d\n", r.Summary.ExcessiveBroadcastDomain)
	fmt.Fprintf(&b, "  Multicast capability:          %d\n\n", r.Summary.MulticastCapability)
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
