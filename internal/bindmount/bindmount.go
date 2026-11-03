package bindmount

import (
	"encoding/json"
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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	DockerSockMounts  int `json:"docker_sock_mounts"`
	ProcSysMounts     int `json:"proc_sys_mounts"`
	HostPathMounts    int `json:"host_path_mounts"`
	WritableBinds     int `json:"writable_binds"`
	RecursiveBinds    int `json:"recursive_binds"`
}

var dockerSockPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
}

var dangerousHostPaths = []string{
	"/proc", "/sys", "/dev",
	"/etc/shadow", "/etc/passwd",
	"/root", "/boot",
	"/lib/modules", "/usr/src",
}

func isDangerousHostPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, d := range dangerousHostPaths {
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

func isDockerSockPath(path string) bool {
	for _, s := range dockerSockPaths {
		if path == s {
			return true
		}
	}
	return false
}

func isWritable(volumeSpec string) bool {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) < 3 {
		return true
	}
	return !strings.Contains(strings.ToLower(parts[2]), "ro")
}

func hostPart(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	return parts[0]
}

func containerPart(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) >= 2 {
		return parts[1]
	}
	return parts[0]
}

func isRecursiveBind(volumeSpec string) bool {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) >= 3 {
		opts := strings.ToLower(parts[2])
		return strings.Contains(opts, "rbind") || strings.Contains(opts, "rslave") || strings.Contains(opts, "rshared")
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, v := range svc.Volumes {
		hp := hostPart(v)
		cp := containerPart(v)
		writable := isWritable(v)

		if isDockerSockPath(hp) || isDockerSockPath(cp) {
			level := "critical"
			sr.Findings = append(sr.Findings, Finding{
				Level:   level,
				Rule:    "docker_sock_bind",
				Message: fmt.Sprintf("Service '%s' bind-mounts container runtime socket '%s'; this grants full host control", svc.Name, hp),
			})
		}

		if strings.HasPrefix(hp, "/") && isDangerousHostPath(hp) {
			level := "high"
			if writable {
				level = "critical"
			}
			sr.Findings = append(sr.Findings, Finding{
				Level:   level,
				Rule:    "dangerous_host_path",
				Message: fmt.Sprintf("Service '%s' bind-mounts dangerous host path '%s' at '%s' (writable: %v)", svc.Name, hp, cp, writable),
			})
		}

		if strings.HasPrefix(hp, "/") && writable && !isDockerSockPath(hp) && !isDangerousHostPath(hp) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "writable_host_bind",
				Message: fmt.Sprintf("Service '%s' bind-mounts host path '%s' writable at '%s'; consider read-only mount", svc.Name, hp, cp),
			})
		}

		if isRecursiveBind(v) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "recursive_bind_mount",
				Message: fmt.Sprintf("Service '%s' uses recursive bind mount options for '%s'; nested mounts propagate to the container", svc.Name, hp),
			})
		}
	}

	return sr
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "docker_sock_bind":
				s.DockerSockMounts++
			case "dangerous_host_path":
				s.ProcSysMounts++
			case "writable_host_bind":
				s.WritableBinds++
			case "recursive_bind_mount":
				s.RecursiveBinds++
			}
		}
	}
	s.HostPathMounts = s.DockerSockMounts + s.ProcSysMounts + s.WritableBinds
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bind Mount Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Docker socket mounts:  %d\n", r.Summary.DockerSockMounts)
	fmt.Fprintf(&b, "  Dangerous host paths:  %d\n", r.Summary.ProcSysMounts)
	fmt.Fprintf(&b, "  Writable host binds:   %d\n", r.Summary.WritableBinds)
	fmt.Fprintf(&b, "  Recursive bind mounts: %d\n\n", r.Summary.RecursiveBinds)
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

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
