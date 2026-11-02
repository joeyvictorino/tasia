package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

var publicResolvers = map[string]string{
	"8.8.8.8":         "Google",
	"8.8.4.4":         "Google",
	"1.1.1.1":         "Cloudflare",
	"1.0.0.1":         "Cloudflare",
	"9.9.9.9":         "Quad9",
	"149.112.112.112": "Quad9",
	"208.67.222.222":  "OpenDNS",
	"208.67.220.220":  "OpenDNS",
}

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name       string    `json:"name"`
	File       string    `json:"file"`
	DNS        []string  `json:"dns,omitempty"`
	DNSSearch  []string  `json:"dns_search,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
	Score      int       `json:"score"`
	Grade      string    `json:"grade"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	WithDNS       int `json:"with_dns"`
	WithIssues    int `json:"with_issues"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			sr := analyzeService(&cf.Services[i], cf.Path)
			services = append(services, sr)
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		if len(s.DNS) > 0 || len(s.DNSSearch) > 0 {
			summary.WithDNS++
		}
		if len(s.Findings) > 0 {
			summary.WithIssues++
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:      svc.Name,
		File:      file,
		DNS:       svc.DNS,
		DNSSearch: svc.DNSSearch,
		Score:     100,
	}

	for _, server := range svc.DNS {
		server = strings.TrimSpace(server)
		if provider, ok := publicResolvers[server]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "public_resolver",
				Detail:   fmt.Sprintf("Uses public DNS resolver %s (%s); could enable DNS tunneling", server, provider),
			})
			sr.Score -= 15
		} else if ip := net.ParseIP(server); ip != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "high",
				Category: "external_dns",
				Detail:   fmt.Sprintf("Uses external DNS server %s; may bypass internal resolution", server),
			})
			sr.Score -= 25
		}
	}

	if len(svc.DNS) > 0 && len(svc.DNSSearch) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "low",
			Category: "missing_dns_search",
			Detail:   "Custom DNS servers set without dns_search restriction",
		})
		sr.Score -= 10
	}

	for _, domain := range svc.DNSSearch {
		domain = strings.TrimSpace(domain)
		if strings.Count(domain, ".") == 0 || strings.HasSuffix(domain, ".") {
			continue
		}
		parts := strings.Split(domain, ".")
		tld := parts[len(parts)-1]
		if tld == "com" || tld == "net" || tld == "org" || tld == "io" {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "low",
				Category: "broad_dns_search",
				Detail:   fmt.Sprintf("dns_search includes public domain %s; may leak internal hostnames", domain),
			})
			sr.Score -= 5
		}
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = scoreToGrade(sr.Score)
	return sr
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS Configuration Audit (%d services, %d with DNS, %d with issues)\n\n",
		r.Summary.TotalServices, r.Summary.WithDNS, r.Summary.WithIssues)

	for _, s := range r.Services {
		if len(s.Findings) == 0 && len(s.DNS) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-30s [%s] score=%d\n", s.Name, s.Grade, s.Score)
		if len(s.DNS) > 0 {
			fmt.Fprintf(&b, "    dns: %s\n", strings.Join(s.DNS, ", "))
		}
		if len(s.DNSSearch) > 0 {
			fmt.Fprintf(&b, "    dns_search: %s\n", strings.Join(s.DNSSearch, ", "))
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Category, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
