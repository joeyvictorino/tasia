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
	NoRootSquash     int `json:"no_root_squash"`
	InsecurePorts    int `json:"insecure_ports"`
	MissingKerberos  int `json:"missing_kerberos"`
	NFSv3NoEncrypt   int `json:"nfsv3_no_encrypt"`
	ExposedPorts     int `json:"exposed_ports"`
	WorldReadable    int `json:"world_readable"`
}

type Report struct {
	Path    string          `json:"path"`
	Results []ServiceResult `json:"results"`
	Summary Summary         `json:"summary"`
}

var nfsImages = []string{"nfs", "nfs-server", "nfs-ganesha", "erichough/nfs", "itsthenetwork/nfs"}

func isNFSImage(image string) bool {
	low := strings.ToLower(image)
	for _, pat := range nfsImages {
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

func isNFSPort(port int) bool {
	return port == 2049 || port == 111
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, Image: svc.Image}
	if !isNFSImage(svc.Image) {
		return sr
	}

	env := envMap(svc)

	if v, ok := env["NFS_EXPORT"]; ok {
		if strings.Contains(v, "*") || strings.Contains(v, "0.0.0.0/0") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "NFS-001", Severity: "high",
				Message: "world-readable NFS export detected", File: file, Service: svc.Name,
			})
		}
	}

	if v, ok := env["NFS_EXPORT_OPTIONS"]; ok {
		if strings.Contains(strings.ToLower(v), "no_root_squash") {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "NFS-002", Severity: "critical",
				Message: "no_root_squash enabled (remote root has local root privileges)", File: file, Service: svc.Name,
			})
		}
	}
	if v, ok := env["NO_ROOT_SQUASH"]; ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "NFS-002", Severity: "critical",
				Message: "no_root_squash enabled via environment variable", File: file, Service: svc.Name,
			})
		}
	}

	if v, ok := env["INSECURE"]; ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "NFS-003", Severity: "medium",
				Message: "insecure port option enabled (allows unprivileged port connections)", File: file, Service: svc.Name,
			})
		}
	}

	if _, ok := env["NFS_KERBEROS"]; !ok {
		if _, ok2 := env["KERBEROS_ENABLED"]; !ok2 {
			if !hasVolumeContaining(svc, "krb5") && !hasVolumeContaining(svc, "keytab") {
				sr.Findings = append(sr.Findings, Finding{
					Rule: "NFS-004", Severity: "medium",
					Message: "Kerberos authentication not configured for NFS", File: file, Service: svc.Name,
				})
			}
		}
	}

	if v, ok := env["NFS_VERSION"]; ok {
		if strings.HasPrefix(v, "3") {
			if _, ok2 := env["NFS_ENCRYPTION"]; !ok2 {
				sr.Findings = append(sr.Findings, Finding{
					Rule: "NFS-005", Severity: "high",
					Message: "NFS v3 without encryption (v3 has no native encryption)", File: file, Service: svc.Name,
				})
			}
		}
	}

	for _, p := range svc.Ports {
		if isNFSPort(p.TargetPort) && p.HostIP != "127.0.0.1" {
			sr.Findings = append(sr.Findings, Finding{
				Rule: "NFS-006", Severity: "medium",
				Message: fmt.Sprintf("NFS port %d exposed to network", p.TargetPort),
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
	s := Summary{}
	s.TotalServices = len(results)
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.AffectedServices++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "NFS-001":
				s.WorldReadable++
			case "NFS-002":
				s.NoRootSquash++
			case "NFS-003":
				s.InsecurePorts++
			case "NFS-004":
				s.MissingKerberos++
			case "NFS-005":
				s.NFSv3NoEncrypt++
			case "NFS-006":
				s.ExposedPorts++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("NFS Export Security Audit\n")
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
