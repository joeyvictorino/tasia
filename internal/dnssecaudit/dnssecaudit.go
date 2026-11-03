package dnssecaudit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	File     string `json:"file"`
	Service  string `json:"service"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	Image    string    `json:"image"`
	Findings []Finding `json:"findings"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	AffectedServices    int `json:"affected_services"`
	TotalFindings       int `json:"total_findings"`
	MissingDNSSEC       int `json:"missing_dnssec"`
	OpenZoneTransfer    int `json:"open_zone_transfer"`
	RecursionEnabled    int `json:"recursion_enabled"`
	MissingTSIG         int `json:"missing_tsig"`
	CachePoisoningRisk  int `json:"cache_poisoning_risk"`
	ExposedWithoutLimit int `json:"exposed_without_limit"`
}

type Report struct {
	Path    string          `json:"path"`
	Results []ServiceResult `json:"results"`
	Summary Summary         `json:"summary"`
}

var dnsImages = []string{"bind9", "bind", "coredns", "powerdns", "unbound", "knot-dns", "nsd", "technitium", "pihole", "adguard"}

func isDNSImage(image string) bool {
	low := strings.ToLower(image)
	for _, pat := range dnsImages {
		if strings.Contains(low, pat) {
			return true
		}
	}
	return false
}

func envMap(svc compose.Service) map[string]string {
	m := make(map[string]string)
	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			m[strings.ToUpper(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func hasVolumeContaining(svc compose.Service, needle string) bool {
	for _, v := range svc.Volumes {
		if strings.Contains(strings.ToLower(v), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func isDNSPort(port int) bool {
	return port == 53 || port == 853 || port == 5353
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, Image: svc.Image}
	if !isDNSImage(svc.Image) {
		return sr
	}

	env := envMap(svc)

	if _, ok := env["DNSSEC_ENABLE"]; !ok {
		if !hasVolumeContaining(svc, "dnssec") && !hasVolumeContaining(svc, "signed") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "DNS-001", Severity: "high",
				Message: "DNSSEC signing not configured", File: file, Service: svc.Name,
			})
		}
	}

	if v, ok := env["ALLOW_TRANSFER"]; ok {
		if v == "any" || v == "*" || v == "0.0.0.0/0" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "DNS-002", Severity: "high",
				Message: "zone transfer (AXFR) open to any host", File: file, Service: svc.Name,
			})
		}
	}

	if v, ok := env["RECURSION"]; ok {
		low := strings.ToLower(v)
		if low == "yes" || low == "true" || low == "1" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "DNS-003", Severity: "medium",
				Message: "recursion enabled (risk of amplification attacks)", File: file, Service: svc.Name,
			})
		}
	}

	if _, ok := env["TSIG_KEY"]; !ok {
		if !hasVolumeContaining(svc, "tsig") && !hasVolumeContaining(svc, "rndc.key") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "DNS-004", Severity: "medium",
				Message: "no TSIG key configured for zone transfer authentication", File: file, Service: svc.Name,
			})
		}
	}

	if _, ok := env["SOURCE_PORT_RANDOMIZE"]; !ok {
		if v, ok2 := env["RANDOMIZE_SOURCE_PORTS"]; !ok2 || strings.ToLower(v) == "false" || v == "0" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "DNS-005", Severity: "medium",
				Message: "source port randomization not confirmed (cache poisoning risk)", File: file, Service: svc.Name,
			})
		}
	}

	for _, p := range svc.Ports {
		if isDNSPort(p.TargetPort) && p.HostIP != "127.0.0.1" {
			if _, ok := env["RATE_LIMIT"]; !ok {
				if _, ok2 := env["DNS_RATE_LIMIT"]; !ok2 {
					sr.Findings = append(sr.Findings, Finding{
						Rule: "DNS-006", Severity: "low",
						Message: fmt.Sprintf("DNS port %d exposed without rate limiting", p.TargetPort),
						File: file, Service: svc.Name,
					})
					break
				}
			}
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
	return Report{Path: c.Root, Results: results, Summary: summarize(results)}
}

func summarize(results []ServiceResult) Summary {
	s := Summary{}
	s.TotalServices = len(results)
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.AffectedServices++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "DNS-001":
				s.MissingDNSSEC++
			case "DNS-002":
				s.OpenZoneTransfer++
			case "DNS-003":
				s.RecursionEnabled++
			case "DNS-004":
				s.MissingTSIG++
			case "DNS-005":
				s.CachePoisoningRisk++
			case "DNS-006":
				s.ExposedWithoutLimit++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("DNS Server Security Audit (DNSSEC)\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Services affected:  %d\n", r.Summary.AffectedServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Results {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", sr.Service, sr.Image)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s][%s] %s\n", f.Rule, f.Severity, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
