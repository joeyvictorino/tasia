package fileperm

import (
	"fmt"
	"regexp"
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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	WorldWritable      int `json:"world_writable"`
	Chmod777           int `json:"chmod_777"`
	SensitivePathMount int `json:"sensitive_path_mount"`
}

var sensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/root/.ssh",
	"/root",
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/proc",
	"/sys",
	"/dev",
}

var sensitiveDirs = []string{
	"/etc",
	"/var/run",
	"/run",
}

var chmod777Re = regexp.MustCompile(`chmod\s+(-R\s+)?777\b`)

func isSensitiveMount(vol string) bool {
	hostPath := strings.SplitN(vol, ":", 2)[0]
	hostPath = strings.TrimSpace(hostPath)
	for _, sp := range sensitivePaths {
		if hostPath == sp || strings.HasPrefix(hostPath, sp+"/") {
			return true
		}
	}
	return false
}

func isWorldWritableMount(vol string) bool {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return false
	}
	hostPath := strings.TrimSpace(parts[0])
	for _, sd := range sensitiveDirs {
		if hostPath == sd || strings.HasPrefix(hostPath, sd+"/") {
			lastPart := parts[len(parts)-1]
			if strings.Contains(lastPart, "rw") || (!strings.Contains(lastPart, "ro") && len(parts) == 2) {
				return true
			}
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	for _, df := range c.Dockerfiles {
		sr := analyzeDockerfile(df)
		r.Services = append(r.Services, sr)
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, vol := range svc.Volumes {
		if isSensitiveMount(vol) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fileperm_sensitive_path_mount",
				Message: fmt.Sprintf("Service '%s' mounts sensitive host path '%s'; this may expose credentials or system configuration", svc.Name, strings.SplitN(vol, ":", 2)[0]),
			})
		}
		if isWorldWritableMount(vol) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fileperm_world_writable_volume",
				Message: fmt.Sprintf("Service '%s' mounts sensitive directory '%s' as writable; consider using read-only (:ro) mode", svc.Name, strings.SplitN(vol, ":", 2)[0]),
			})
		}
	}

	return sr
}

func analyzeDockerfile(df collect.Dockerfile) ServiceResult {
	sr := ServiceResult{Service: df.Path, File: df.Path}

	for _, line := range strings.Split(df.Content, "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "RUN ") {
			cmd := trimmed[4:]
			if chmod777Re.MatchString(cmd) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "fileperm_chmod_777",
					Message: fmt.Sprintf("Dockerfile '%s' uses chmod 777 which grants world-readable/writable permissions; use more restrictive permissions", df.Path),
				})
			}
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "fileperm_world_writable_volume":
				s.WorldWritable++
			case "fileperm_chmod_777":
				s.Chmod777++
			case "fileperm_sensitive_path_mount":
				s.SensitivePathMount++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "File Permission Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  World-writable volumes: %d\n", r.Summary.WorldWritable)
	fmt.Fprintf(&b, "  chmod 777 usage:        %d\n", r.Summary.Chmod777)
	fmt.Fprintf(&b, "  Sensitive path mounts:  %d\n\n", r.Summary.SensitivePathMount)
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
