package hostpath

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
	TotalServices   int `json:"total_services"`
	TotalFindings   int `json:"total_findings"`
	RootMounts      int `json:"root_mounts"`
	DockerSockets   int `json:"docker_sockets"`
	ProcSysMounts   int `json:"proc_sys_mounts"`
	SensitiveRW     int `json:"sensitive_rw"`
}

var sensitiveHostPaths = map[string]string{
	"/":                      "root filesystem",
	"/etc":                   "system configuration",
	"/var/run/docker.sock":   "Docker socket",
	"/run/docker.sock":       "Docker socket",
	"/proc":                  "kernel process info",
	"/sys":                   "kernel sysfs",
	"/var/run":               "runtime state",
	"/root":                  "root home directory",
	"/boot":                  "boot configuration",
	"/dev":                   "device nodes",
	"/var/lib/docker":        "Docker data",
	"/var/lib/containerd":    "containerd data",
}

func isDockerSocket(path string) bool {
	p := strings.TrimSuffix(path, "/")
	return p == "/var/run/docker.sock" || p == "/run/docker.sock"
}

func isProcSys(path string) bool {
	p := strings.TrimSuffix(path, "/")
	return p == "/proc" || strings.HasPrefix(p, "/proc/") ||
		p == "/sys" || strings.HasPrefix(p, "/sys/")
}

func isRootMount(path string) bool {
	return strings.TrimSuffix(path, "/") == ""
}

func isSensitive(path string) bool {
	p := strings.TrimSuffix(path, "/")
	if _, ok := sensitiveHostPaths[p]; ok {
		return true
	}
	for prefix := range sensitiveHostPaths {
		if prefix != "/" && strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func isReadOnly(opts []string) bool {
	for _, o := range opts {
		if strings.TrimSpace(o) == "ro" {
			return true
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
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		host := parts[0]
		if !strings.HasPrefix(host, "/") {
			continue
		}

		var opts []string
		if len(parts) >= 3 {
			opts = strings.Split(parts[2], ",")
		}
		hostNorm := strings.TrimSuffix(host, "/")

		if hostNorm == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "hostpath_root_mount",
				Message: fmt.Sprintf("Service '%s' mounts the host root filesystem '/'; this grants full host access and enables container escape", svc.Name),
			})
		}

		if isDockerSocket(host) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "hostpath_docker_socket",
				Message: fmt.Sprintf("Service '%s' mounts the Docker socket '%s'; this enables container escape via Docker API", svc.Name, host),
			})
		}

		if isProcSys(host) {
			level := "high"
			if isReadOnly(opts) {
				level = "medium"
			}
			sr.Findings = append(sr.Findings, Finding{
				Level:   level,
				Rule:    "hostpath_proc_sys",
				Message: fmt.Sprintf("Service '%s' mounts host '%s'; access to /proc or /sys can leak kernel info or enable privilege escalation", svc.Name, host),
			})
		}

		if isSensitive(host) && !isReadOnly(opts) && !isDockerSocket(host) && hostNorm != "" && !isProcSys(host) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "hostpath_sensitive_rw",
				Message: fmt.Sprintf("Service '%s' mounts sensitive host path '%s' read-write; use read-only mount or avoid mounting sensitive paths", svc.Name, host),
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
			case "hostpath_root_mount":
				s.RootMounts++
			case "hostpath_docker_socket":
				s.DockerSockets++
			case "hostpath_proc_sys":
				s.ProcSysMounts++
			case "hostpath_sensitive_rw":
				s.SensitiveRW++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host Path Mount Risk Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Root mounts:          %d\n", r.Summary.RootMounts)
	fmt.Fprintf(&b, "  Docker sockets:       %d\n", r.Summary.DockerSockets)
	fmt.Fprintf(&b, "  /proc or /sys mounts: %d\n", r.Summary.ProcSysMounts)
	fmt.Fprintf(&b, "  Sensitive RW mounts:  %d\n\n", r.Summary.SensitiveRW)
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
