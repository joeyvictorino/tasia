package storagedriver

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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	HostMountRW        int `json:"host_mount_rw"`
	DockerSockMount    int `json:"docker_sock_mount"`
	SensitiveMount     int `json:"sensitive_mount"`
	NoReadOnlyRoot     int `json:"no_read_only_root"`
	TmpfsNoSizeLimit   int `json:"tmpfs_no_size_limit"`
	PrivilegedStorage  int `json:"privileged_storage"`
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
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, vol := range svc.Volumes {
		lower := strings.ToLower(vol)

		if strings.Contains(lower, "/var/run/docker.sock") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "storagedriver_docker_sock",
				Message: fmt.Sprintf("Service '%s' mounts Docker socket '%s'; grants full control over the Docker daemon", svc.Name, vol),
			})
			continue
		}

		for _, sensitive := range []string{"/etc/shadow", "/etc/passwd", "/root", "/home"} {
			if strings.Contains(lower, sensitive) && !strings.Contains(lower, ":ro") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "storagedriver_sensitive_mount",
					Message: fmt.Sprintf("Service '%s' mounts sensitive host path '%s' without read-only flag", svc.Name, vol),
				})
				break
			}
		}

		parts := strings.SplitN(vol, ":", 3)
		if len(parts) >= 2 && strings.HasPrefix(parts[0], "/") {
			isRO := len(parts) == 3 && strings.Contains(parts[2], "ro")
			if !isRO {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "storagedriver_host_mount_rw",
					Message: fmt.Sprintf("Service '%s' bind-mounts host path '%s' read-write; consider adding :ro", svc.Name, vol),
				})
			}
		}
	}

	if !svc.ReadOnly {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "storagedriver_no_readonly_root",
			Message: fmt.Sprintf("Service '%s' does not set read_only: true; writable root filesystem allows malware persistence", svc.Name),
		})
	}

	for _, t := range svc.Tmpfs {
		if !strings.Contains(t, "size=") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "storagedriver_tmpfs_no_size",
				Message: fmt.Sprintf("Service '%s' mounts tmpfs '%s' without size limit; can exhaust host memory", svc.Name, t),
			})
		}
	}

	if svc.Privileged && len(svc.Volumes) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "storagedriver_privileged_storage",
			Message: fmt.Sprintf("Service '%s' is privileged with volume mounts; can access any host storage", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "storagedriver_host_mount_rw":
				s.HostMountRW++
			case "storagedriver_docker_sock":
				s.DockerSockMount++
			case "storagedriver_sensitive_mount":
				s.SensitiveMount++
			case "storagedriver_no_readonly_root":
				s.NoReadOnlyRoot++
			case "storagedriver_tmpfs_no_size":
				s.TmpfsNoSizeLimit++
			case "storagedriver_privileged_storage":
				s.PrivilegedStorage++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Storage Driver Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host mount RW:          %d\n", r.Summary.HostMountRW)
	fmt.Fprintf(&b, "  Docker socket mount:    %d\n", r.Summary.DockerSockMount)
	fmt.Fprintf(&b, "  Sensitive mount:        %d\n", r.Summary.SensitiveMount)
	fmt.Fprintf(&b, "  No read-only root:      %d\n", r.Summary.NoReadOnlyRoot)
	fmt.Fprintf(&b, "  Tmpfs no size limit:    %d\n", r.Summary.TmpfsNoSizeLimit)
	fmt.Fprintf(&b, "  Privileged storage:     %d\n\n", r.Summary.PrivilegedStorage)
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
