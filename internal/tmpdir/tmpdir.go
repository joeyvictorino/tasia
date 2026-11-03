package tmpdir

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
	SharedTmpMounts  int `json:"shared_tmp_mounts"`
	NoExecViolations int `json:"noexec_violations"`
	InterserviceComm int `json:"interservice_comm"`
}

var tmpPaths = []string{"/tmp", "/var/tmp", "/dev/shm"}

func isTmpPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, t := range tmpPaths {
		if path == t || strings.HasPrefix(path, t+"/") {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}

	namedVolUsage := buildNamedVolumeUsage(c)

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, namedVolUsage)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func buildNamedVolumeUsage(c *collect.Collected) map[string][]string {
	usage := make(map[string][]string)
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, v := range svc.Volumes {
				parts := strings.Split(v, ":")
				if len(parts) < 2 {
					continue
				}
				host := parts[0]
				container := parts[1]
				if isTmpPath(container) && !strings.HasPrefix(host, "/") && !strings.HasPrefix(host, ".") {
					usage[host] = append(usage[host], svc.Name)
				}
			}
		}
	}
	return usage
}

func analyzeService(svc compose.Service, file string, namedVolUsage map[string][]string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		host := parts[0]
		container := parts[1]
		var opts []string
		if len(parts) >= 3 {
			opts = strings.Split(parts[2], ",")
		}

		if !isTmpPath(container) {
			continue
		}

		if isSharedHostTmp(host, container) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "shared_tmp_mount",
				Message: fmt.Sprintf("Service '%s' mounts host temp '%s' to '%s'; shared temp directories enable symlink attacks and data leakage between containers", svc.Name, host, container),
			})
		}

		if !strings.HasPrefix(host, "/") && !strings.HasPrefix(host, ".") {
			if users, ok := namedVolUsage[host]; ok && len(users) > 1 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "tmp_interservice_comm",
					Message: fmt.Sprintf("Service '%s' shares named volume '%s' at '%s' with %s; temp directories used for inter-service communication are vulnerable to symlink races", svc.Name, host, container, formatServiceList(users, svc.Name)),
				})
			}
		}

		if !hasOption(opts, "noexec") && !hasOption(opts, "ro") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "tmp_no_noexec",
				Message: fmt.Sprintf("Service '%s' mounts '%s' writable without noexec; executables can be staged in temp directory", svc.Name, container),
			})
		}
	}

	for _, t := range svc.Tmpfs {
		path, opts := parseTmpfsEntry(t)
		if !isTmpPath(path) {
			continue
		}
		if !hasOption(opts, "noexec") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "tmp_no_noexec",
				Message: fmt.Sprintf("Service '%s' mounts tmpfs at '%s' without noexec; executables can be staged in temp directory", svc.Name, path),
			})
		}
	}

	return sr
}

func isSharedHostTmp(host, container string) bool {
	host = strings.TrimSuffix(host, "/")
	if strings.HasPrefix(host, "/") || strings.HasPrefix(host, ".") {
		return isTmpPath(host)
	}
	return false
}

func parseTmpfsEntry(entry string) (string, []string) {
	parts := strings.SplitN(entry, ":", 2)
	path := strings.TrimSpace(parts[0])
	if len(parts) < 2 {
		return path, nil
	}
	return path, strings.Split(parts[1], ",")
}

func hasOption(opts []string, name string) bool {
	for _, o := range opts {
		if strings.TrimSpace(o) == name {
			return true
		}
	}
	return false
}

func formatServiceList(services []string, exclude string) string {
	var others []string
	for _, s := range services {
		if s != exclude {
			others = append(others, "'"+s+"'")
		}
	}
	if len(others) == 0 {
		return "other services"
	}
	return strings.Join(others, ", ")
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "shared_tmp_mount":
				s.SharedTmpMounts++
			case "tmp_no_noexec":
				s.NoExecViolations++
			case "tmp_interservice_comm":
				s.InterserviceComm++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Temp Directory Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Shared temp mounts:      %d\n", r.Summary.SharedTmpMounts)
	fmt.Fprintf(&b, "  No-exec violations:      %d\n", r.Summary.NoExecViolations)
	fmt.Fprintf(&b, "  Inter-service temp comm: %d\n\n", r.Summary.InterserviceComm)
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
