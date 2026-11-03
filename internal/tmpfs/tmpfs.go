package tmpfs

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Mount    string `json:"mount"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type ServiceResult struct {
	Service    string    `json:"service"`
	File       string    `json:"file"`
	TmpfsMounts []string `json:"tmpfs_mounts"`
	Findings   []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	ServicesWithTmpfs int `json:"services_with_tmpfs"`
	TotalMounts      int `json:"total_mounts"`
	TotalFindings    int `json:"total_findings"`
}

var sensitivePaths = []string{
	"/etc",
	"/var/run",
	"/var/lib",
	"/root",
	"/home",
	"/proc",
	"/sys",
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service:     svc.Name,
		File:        file,
		TmpfsMounts: svc.Tmpfs,
	}

	for _, mount := range svc.Tmpfs {
		path, opts := parseTmpfsMount(mount)

		if !hasSizeLimit(opts) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, Mount: mount,
				Category: "size",
				Severity: "medium",
				Message:  fmt.Sprintf("tmpfs at %s has no size limit; can consume all memory", path),
			})
		}

		if isSensitivePath(path) {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, Mount: mount,
				Category: "sensitive_path",
				Severity: "high",
				Message:  fmt.Sprintf("tmpfs mounted at sensitive path %s", path),
			})
		}

		if !hasOption(opts, "noexec") {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, Mount: mount,
				Category: "exec",
				Severity: "low",
				Message:  fmt.Sprintf("tmpfs at %s missing noexec option", path),
			})
		}

		if !hasOption(opts, "nosuid") {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, Mount: mount,
				Category: "suid",
				Severity: "low",
				Message:  fmt.Sprintf("tmpfs at %s missing nosuid option", path),
			})
		}
	}

	// Also check volumes for tmpfs type mounts
	for _, vol := range svc.Volumes {
		if strings.HasPrefix(vol, "tmpfs:") || strings.Contains(vol, ":tmpfs") {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, Mount: vol,
				Category: "volume_tmpfs",
				Severity: "low",
				Message:  "tmpfs configured via volume mount; prefer dedicated tmpfs: block for clarity",
			})
		}
	}

	return sr
}

func parseTmpfsMount(mount string) (path string, opts string) {
	parts := strings.SplitN(mount, ":", 2)
	path = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		opts = strings.TrimSpace(parts[1])
	}
	return
}

func hasSizeLimit(opts string) bool {
	if opts == "" {
		return false
	}
	for _, opt := range strings.Split(opts, ",") {
		if strings.HasPrefix(strings.TrimSpace(opt), "size=") {
			return true
		}
	}
	return false
}

func hasOption(opts string, name string) bool {
	if opts == "" {
		return false
	}
	for _, opt := range strings.Split(opts, ",") {
		if strings.TrimSpace(opt) == name {
			return true
		}
	}
	return false
}

func isSensitivePath(path string) bool {
	cleaned := strings.TrimRight(path, "/")
	for _, sp := range sensitivePaths {
		if cleaned == sp || strings.HasPrefix(cleaned, sp+"/") {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, svc := range services {
		if len(svc.TmpfsMounts) > 0 {
			s.ServicesWithTmpfs++
			s.TotalMounts += len(svc.TmpfsMounts)
		}
		s.TotalFindings += len(svc.Findings)
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Tmpfs Mount Audit (%d services, %d with tmpfs, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.ServicesWithTmpfs, r.Summary.TotalFindings)
	for _, svc := range r.Services {
		if len(svc.TmpfsMounts) == 0 && len(svc.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-30s tmpfs mounts: %d\n", svc.Service, len(svc.TmpfsMounts))
		fmt.Fprintf(&b, "    file: %s\n", svc.File)
		for _, m := range svc.TmpfsMounts {
			fmt.Fprintf(&b, "    mount: %s\n", m)
		}
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Category, f.Message)
		}
		b.WriteString("\n")
	}
	if r.Summary.ServicesWithTmpfs == 0 {
		b.WriteString("  No tmpfs mounts found.\n")
	}
	return b.String()
}
