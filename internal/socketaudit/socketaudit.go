package socketaudit

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
	Sockets  []string  `json:"sockets,omitempty"`
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
	WithSocketMounts int `json:"with_socket_mounts"`
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

var knownDangerousSockets = map[string]string{
	"/var/run/docker.sock":              "docker",
	"/run/docker.sock":                  "docker",
	"/var/run/containerd/containerd.sock": "containerd",
	"/run/containerd/containerd.sock":    "containerd",
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}
	var sockets []socketMount

	for _, v := range svc.Volumes {
		host, container, opts := parseVolume(v)
		if isSocketPath(host) || isSocketPath(container) {
			sockets = append(sockets, socketMount{
				host:      host,
				container: container,
				opts:      opts,
			})
			sr.Sockets = append(sr.Sockets, host)
		}
	}

	for _, sm := range sockets {
		kind, known := knownDangerousSockets[sm.host]

		if kind == "docker" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "socket_docker_mounted",
				Message: fmt.Sprintf("Service '%s' mounts Docker socket '%s'; grants near-root host access", svc.Name, sm.host),
			})
			if !hasOpt(sm.opts, "ro") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "socket_docker_readonly",
					Message: fmt.Sprintf("Service '%s' mounts Docker socket read-write; use :ro if read-only access is sufficient", svc.Name),
				})
			}
		}

		if kind == "containerd" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "socket_containerd_mounted",
				Message: fmt.Sprintf("Service '%s' mounts containerd socket '%s'; grants container runtime access", svc.Name, sm.host),
			})
		}

		if !known {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "socket_unknown_exposed",
				Message: fmt.Sprintf("Service '%s' exposes unknown socket '%s'; verify it is required", svc.Name, sm.host),
			})
		}

		if !hasOpt(sm.opts, "ro") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "socket_world_writable",
				Message: fmt.Sprintf("Service '%s' mounts socket '%s' read-write; any process in the container can write to it", svc.Name, sm.host),
			})
		}
	}

	if len(sockets) > 1 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "socket_multiple_exposed",
			Message: fmt.Sprintf("Service '%s' exposes %d sockets; broad daemon access increases attack surface", svc.Name, len(sockets)),
		})
	}

	return sr
}

type socketMount struct {
	host      string
	container string
	opts      []string
}

func parseVolume(vol string) (string, string, []string) {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return vol, vol, nil
	}
	host := parts[0]
	container := parts[1]
	var opts []string
	if len(parts) >= 3 {
		opts = strings.Split(parts[2], ",")
	}
	return host, container, opts
}

func isSocketPath(path string) bool {
	return strings.HasSuffix(path, ".sock") || strings.HasSuffix(path, ".socket")
}

func hasOpt(opts []string, name string) bool {
	for _, o := range opts {
		if strings.TrimSpace(o) == name {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		s.TotalFindings += len(sr.Findings)
		if len(sr.Sockets) > 0 {
			s.WithSocketMounts++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Socket Exposure Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Services with socket mounts: %d\n\n", r.Summary.WithSocketMounts)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s", sr.Service)
		if len(sr.Sockets) > 0 {
			fmt.Fprintf(&b, " sockets: %s", strings.Join(sr.Sockets, ", "))
		}
		b.WriteString("\n")
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
