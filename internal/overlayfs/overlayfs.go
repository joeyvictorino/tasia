package overlayfs

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

type DockerfileResult struct {
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path        string             `json:"path"`
	Services    []ServiceResult    `json:"services"`
	Dockerfiles []DockerfileResult `json:"dockerfiles"`
	Summary     Summary            `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	TotalDockerfiles int `json:"total_dockerfiles"`
	TotalFindings    int `json:"total_findings"`
	WritableOverlay  int `json:"writable_overlay"`
	SensitiveMount   int `json:"sensitive_mount"`
	MissingNoexec    int `json:"missing_noexec"`
	PrivilegedFS     int `json:"privileged_fs"`
}

func hasOverlayVolume(volumes []string) bool {
	for _, v := range volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "overlay") || strings.Contains(lower, "upperdir") || strings.Contains(lower, "workdir=") {
			return true
		}
	}
	return false
}

func hasSensitiveMountPath(volumes []string) bool {
	sensitive := []string{"/etc", "/var/run", "/proc", "/sys", "/dev"}
	for _, v := range volumes {
		parts := strings.SplitN(v, ":", 2)
		if len(parts) < 2 {
			continue
		}
		target := parts[1]
		for _, s := range sensitive {
			if strings.HasPrefix(target, s) {
				return true
			}
		}
	}
	return false
}

func isMountReadOnly(volume string) bool {
	parts := strings.Split(volume, ":")
	if len(parts) >= 3 {
		return strings.Contains(parts[2], "ro")
	}
	return false
}

func analyzeService(svc compose.Service, composePath string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: composePath}

	if hasOverlayVolume(svc.Volumes) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "overlay_volume_mount",
			Message: fmt.Sprintf("service %q mounts overlay-related volume", svc.Name),
		})
	}

	if hasSensitiveMountPath(svc.Volumes) {
		for _, v := range svc.Volumes {
			parts := strings.SplitN(v, ":", 2)
			if len(parts) >= 2 && !isMountReadOnly(v) {
				sensitive := []string{"/etc", "/var/run", "/proc", "/sys", "/dev"}
				for _, s := range sensitive {
					if strings.HasPrefix(parts[1], s) {
						sr.Findings = append(sr.Findings, Finding{
							Level:   "warning",
							Rule:    "sensitive_path_writable",
							Message: fmt.Sprintf("service %q mounts sensitive path %s writable", svc.Name, parts[1]),
						})
						break
					}
				}
			}
		}
	}

	if svc.Privileged && len(svc.Volumes) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "privileged_with_volumes",
			Message: fmt.Sprintf("service %q is privileged with volume mounts — can manipulate filesystem layers", svc.Name),
		})
	}

	if !svc.ReadOnly && len(svc.Volumes) > 3 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "no_readonly_many_volumes",
			Message: fmt.Sprintf("service %q has %d volume mounts without read_only rootfs", svc.Name, len(svc.Volumes)),
		})
	}

	return sr
}

func analyzeDockerfile(df collect.Dockerfile) DockerfileResult {
	dr := DockerfileResult{File: df.Path}
	content := strings.ToLower(df.Content)

	if strings.Contains(content, "mount -t overlay") || strings.Contains(content, "mount -t overlayfs") {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "warning",
			Rule:    "overlay_mount_in_build",
			Message: fmt.Sprintf("Dockerfile %s mounts overlay filesystem during build", df.Path),
		})
	}

	if strings.Contains(content, "fuse-overlayfs") {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "info",
			Rule:    "fuse_overlayfs_usage",
			Message: fmt.Sprintf("Dockerfile %s uses fuse-overlayfs", df.Path),
		})
	}

	return dr
}

func Analyze(c *collect.Collected) Report {
	var services []ServiceResult
	var dockerfiles []DockerfileResult

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			services = append(services, sr)
		}
	}

	for _, df := range c.Dockerfiles {
		dr := analyzeDockerfile(df)
		dockerfiles = append(dockerfiles, dr)
	}

	return Report{
		Path:        c.Root,
		Services:    services,
		Dockerfiles: dockerfiles,
		Summary:     summarize(services, dockerfiles),
	}
}

func summarize(services []ServiceResult, dockerfiles []DockerfileResult) Summary {
	s := Summary{
		TotalServices:    len(services),
		TotalDockerfiles: len(dockerfiles),
	}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "overlay_volume_mount":
				s.WritableOverlay++
			case "sensitive_path_writable":
				s.SensitiveMount++
			case "no_readonly_many_volumes":
				s.MissingNoexec++
			case "privileged_with_volumes":
				s.PrivilegedFS++
			}
		}
	}
	for _, dr := range dockerfiles {
		s.TotalFindings += len(dr.Findings)
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("OverlayFS Security Analysis\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	b.WriteString(fmt.Sprintf("Root: %s\n", r.Path))
	b.WriteString(fmt.Sprintf("Services: %d  Dockerfiles: %d  Findings: %d\n\n",
		r.Summary.TotalServices, r.Summary.TotalDockerfiles, r.Summary.TotalFindings))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("Service: %s (%s)\n", sr.Service, sr.File))
		for _, f := range sr.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Level, f.Rule, f.Message))
		}
		b.WriteString("\n")
	}

	for _, dr := range r.Dockerfiles {
		if len(dr.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("Dockerfile: %s\n", dr.File))
		for _, f := range dr.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Level, f.Rule, f.Message))
		}
		b.WriteString("\n")
	}

	return b.String()
}
