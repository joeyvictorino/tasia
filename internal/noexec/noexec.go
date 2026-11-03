package noexec

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
	TotalServices int `json:"total_services"`
	TotalFindings int `json:"total_findings"`
	WithTmpfs     int `json:"with_tmpfs"`
	WithVolumes   int `json:"with_volumes"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services, c)
	return r
}

var sensitivePaths = map[string]string{
	"/tmp":  "noexec_tmp_writable",
	"/dev":  "noexec_dev_missing",
	"/run":  "noexec_run_missing",
	"/home": "noexec_home_writable",
}

var sensitiveLevels = map[string]string{
	"noexec_tmp_writable":  "medium",
	"noexec_dev_missing":   "high",
	"noexec_run_missing":   "low",
	"noexec_home_writable": "medium",
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, t := range svc.Tmpfs {
		path, opts := parseTmpfsEntry(t)
		if !hasOption(opts, "noexec") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "noexec_tmpfs_missing",
				Message: fmt.Sprintf("Service '%s' mounts tmpfs at '%s' without noexec; executables can be staged there", svc.Name, path),
			})
		}
	}

	for _, v := range svc.Volumes {
		container, opts := parseVolumeMount(v)
		if container == "" {
			continue
		}
		for sensPath, rule := range sensitivePaths {
			if containerPathMatches(container, sensPath) && !hasOption(opts, "noexec") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   sensitiveLevels[rule],
					Rule:    rule,
					Message: fmt.Sprintf("Service '%s' mounts '%s' without noexec option", svc.Name, container),
				})
			}
		}
		if isWritableVolume(container, opts) && !hasOption(opts, "noexec") {
			if isSensitiveWritable(container) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "noexec_writable_volume",
					Message: fmt.Sprintf("Service '%s' has writable volume at '%s' without noexec; binaries can be dropped", svc.Name, container),
				})
			}
		}
	}

	return sr
}

func parseTmpfsEntry(entry string) (string, []string) {
	parts := strings.SplitN(entry, ":", 2)
	path := strings.TrimSpace(parts[0])
	if len(parts) < 2 {
		return path, nil
	}
	return path, strings.Split(parts[1], ",")
}

func parseVolumeMount(vol string) (string, []string) {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return "", nil
	}
	container := parts[1]
	var opts []string
	if len(parts) >= 3 {
		opts = strings.Split(parts[2], ",")
	}
	return container, opts
}

func hasOption(opts []string, name string) bool {
	for _, o := range opts {
		if strings.TrimSpace(o) == name {
			return true
		}
	}
	return false
}

func containerPathMatches(container, target string) bool {
	container = strings.TrimSuffix(container, "/")
	return container == target || strings.HasPrefix(container, target+"/")
}

func isWritableVolume(container string, opts []string) bool {
	return !hasOption(opts, "ro")
}

func isSensitiveWritable(container string) bool {
	writable := []string{"/var/tmp", "/opt", "/usr/local", "/srv"}
	for _, w := range writable {
		if containerPathMatches(container, w) {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult, c *collect.Collected) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		s.TotalFindings += len(sr.Findings)
	}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if len(svc.Tmpfs) > 0 {
				s.WithTmpfs++
			}
			if len(svc.Volumes) > 0 {
				s.WithVolumes++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "No-Exec Mount Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Services with tmpfs: %d\n", r.Summary.WithTmpfs)
	fmt.Fprintf(&b, "  Services with volumes: %d\n\n", r.Summary.WithVolumes)
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
