package nfsaudit

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
	TotalServices    int `json:"total_services"`
	AffectedServices int `json:"affected_services"`
	TotalFindings    int `json:"total_findings"`
	NoAuthExport     int `json:"no_auth_export"`
	WorldReadable    int `json:"world_readable"`
	NoRootSquash     int `json:"no_root_squash"`
	InsecurePort     int `json:"insecure_port"`
	MissingKerberos  int `json:"missing_kerberos"`
	ExposedPort      int `json:"exposed_port"`
}

type Report struct {
	Path    string          `json:"path"`
	Results []ServiceResult `json:"results"`
	Summary Summary         `json:"summary"`
}

func isNFSService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "nfs") || strings.Contains(combined, "nfsd") || strings.Contains(combined, "ganesha")
}

func envMap(svc compose.Service) map[string]string {
	m := map[string]string{}
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
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, Image: svc.Image}
	if !isNFSService(svc) {
		return sr
	}

	env := envMap(svc)

	if v, ok := env["NFS_EXPORT_OPTIONS"]; ok {
		low := strings.ToLower(v)
		if !strings.Contains(low, "sec=") || strings.Contains(low, "sec=sys") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "no_auth_export", Severity: "high",
				Message: "NFS export uses sys (AUTH_SYS) authentication instead of Kerberos",
				File: file, Service: svc.Name,
			})
		}
	} else if !hasVolumeContaining(svc, "exports") {
		sr.Findings = append(sr.Findings, Finding{
			Rule: "no_auth_export", Severity: "high",
			Message: "NFS service without explicit export configuration",
			File: file, Service: svc.Name,
		})
	}

	if v, ok := env["NFS_EXPORT_ALLOWED"]; ok {
		low := strings.ToLower(v)
		if low == "*" || low == "0.0.0.0/0" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "world_readable", Severity: "critical",
				Message: fmt.Sprintf("NFS export allows access from all hosts (%s)", v),
				File: file, Service: svc.Name,
			})
		}
	}

	if v, ok := env["NFS_EXPORT_OPTIONS"]; ok {
		low := strings.ToLower(v)
		if strings.Contains(low, "no_root_squash") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "no_root_squash", Severity: "high",
				Message: "NFS export with no_root_squash allows remote root access",
				File: file, Service: svc.Name,
			})
		}
	}

	if v, ok := env["NFS_EXPORT_OPTIONS"]; ok {
		low := strings.ToLower(v)
		if strings.Contains(low, "insecure") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "insecure_port", Severity: "medium",
				Message: "NFS export allows connections from unprivileged ports",
				File: file, Service: svc.Name,
			})
		}
	}

	hasKerberos := false
	if v, ok := env["NFS_KERBEROS"]; ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			hasKerberos = true
		}
	}
	if v, ok := env["NFS_EXPORT_OPTIONS"]; ok {
		low := strings.ToLower(v)
		if strings.Contains(low, "sec=krb5") {
			hasKerberos = true
		}
	}
	if hasVolumeContaining(svc, "krb5") || hasVolumeContaining(svc, "keytab") {
		hasKerberos = true
	}
	if !hasKerberos {
		sr.Findings = append(sr.Findings, Finding{
			Rule: "missing_kerberos", Severity: "medium",
			Message: "NFS service without Kerberos authentication configured",
			File: file, Service: svc.Name,
		})
	}

	for _, port := range svc.Ports {
		if port.TargetPort == 2049 && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "exposed_port", Severity: "high",
				Message: fmt.Sprintf("NFS port 2049 exposed on all interfaces (%s)", port.Raw),
				File: file, Service: svc.Name,
			})
			break
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
	var s Summary
	s.TotalServices = len(results)
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.AffectedServices++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "no_auth_export":
				s.NoAuthExport++
			case "world_readable":
				s.WorldReadable++
			case "no_root_squash":
				s.NoRootSquash++
			case "insecure_port":
				s.InsecurePort++
			case "missing_kerberos":
				s.MissingKerberos++
			case "exposed_port":
				s.ExposedPort++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("NFS Share Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	if r.Path != "" {
		fmt.Fprintf(&b, "  Path: %s\n", r.Path)
	}
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Services affected:  %d\n", r.Summary.AffectedServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Results {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s\n", sr.Service)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] [%s] %s\n", f.Rule, f.Severity, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
