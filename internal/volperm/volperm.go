package volperm

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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	WritableHostMount    int `json:"writable_host_mount"`
	SensitivePathMount   int `json:"sensitive_path_mount"`
	DockerSocketMount    int `json:"docker_socket_mount"`
	RootMountRW          int `json:"root_mount_rw"`
	RecursiveBindMount   int `json:"recursive_bind_mount"`
	WorldWritableTarget  int `json:"world_writable_target"`
}

var sensitivePaths = map[string]string{
	"/etc":               "host system configuration directory",
	"/etc/shadow":        "password shadow file",
	"/etc/passwd":        "user account file",
	"/etc/sudoers":       "sudo privileges file",
	"/root":              "root user home directory",
	"/proc":              "kernel process information pseudo-filesystem",
	"/sys":               "kernel sysfs interface",
	"/boot":              "boot loader directory",
	"/var/run/docker.sock": "Docker daemon socket",
	"/run/docker.sock":    "Docker daemon socket",
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
		parts := strings.Split(vol, ":")
		if len(parts) < 2 {
			continue
		}
		hostPath := parts[0]
		mode := ""
		if len(parts) >= 3 {
			mode = parts[2]
		}

		isRW := mode == "" || strings.Contains(mode, "rw")
		isDockerSocket := strings.Contains(hostPath, "docker.sock")

		if isDockerSocket {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "volperm_docker_socket",
				Message: fmt.Sprintf("Service '%s' mounts Docker socket '%s'; allows full host container control", svc.Name, hostPath),
			})
			continue
		}

		if hostPath == "/" && isRW {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "volperm_root_rw",
				Message: fmt.Sprintf("Service '%s' mounts host root / as writable; complete host filesystem access", svc.Name),
			})
			continue
		}

		for sensPath, desc := range sensitivePaths {
			if strings.HasPrefix(hostPath, sensPath) && isRW {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "volperm_sensitive_path",
					Message: fmt.Sprintf("Service '%s' mounts sensitive host path '%s' as writable; %s", svc.Name, hostPath, desc),
				})
				break
			}
		}

		if strings.HasPrefix(hostPath, "/") && isRW && !isDockerSocket {
			isSensitive := false
			for sensPath := range sensitivePaths {
				if strings.HasPrefix(hostPath, sensPath) {
					isSensitive = true
					break
				}
			}
			if !isSensitive && hostPath != "/" {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "volperm_writable_host",
					Message: fmt.Sprintf("Service '%s' mounts host path '%s' as writable; consider using :ro if write access is not needed", svc.Name, hostPath),
				})
			}
		}

		if strings.Contains(mode, "rshared") || strings.Contains(mode, "shared") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "volperm_recursive_bind",
				Message: fmt.Sprintf("Service '%s' volume '%s' uses shared bind propagation; mount events propagate bidirectionally to host", svc.Name, vol),
			})
		}

		if strings.Contains(vol, "/tmp") && isRW {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "volperm_world_writable",
				Message: fmt.Sprintf("Service '%s' mounts world-writable path '%s'; may allow cross-container data tampering", svc.Name, hostPath),
			})
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
			case "volperm_writable_host":
				s.WritableHostMount++
			case "volperm_sensitive_path":
				s.SensitivePathMount++
			case "volperm_docker_socket":
				s.DockerSocketMount++
			case "volperm_root_rw":
				s.RootMountRW++
			case "volperm_recursive_bind":
				s.RecursiveBindMount++
			case "volperm_world_writable":
				s.WorldWritableTarget++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Volume Permission Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Writable host mounts:    %d\n", r.Summary.WritableHostMount)
	fmt.Fprintf(&b, "  Sensitive path mounts:   %d\n", r.Summary.SensitivePathMount)
	fmt.Fprintf(&b, "  Docker socket mounts:    %d\n", r.Summary.DockerSocketMount)
	fmt.Fprintf(&b, "  Root / as writable:      %d\n", r.Summary.RootMountRW)
	fmt.Fprintf(&b, "  Recursive bind mounts:   %d\n", r.Summary.RecursiveBindMount)
	fmt.Fprintf(&b, "  World-writable targets:  %d\n\n", r.Summary.WorldWritableTarget)
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
