package filedescriptor

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	ExcessiveNofile     int `json:"excessive_nofile"`
	UnlimitedNofile     int `json:"unlimited_nofile"`
	DevFdMount          int `json:"dev_fd_mount"`
	ProcFdMount         int `json:"proc_fd_mount"`
	SocketMount         int `json:"socket_mount"`
	NoNofileLimit       int `json:"no_nofile_limit"`
}

const excessiveNofileThreshold int64 = 1048576

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

	if ul, ok := svc.Ulimits["nofile"]; ok {
		if ul.Soft == -1 || ul.Hard == -1 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fd_unlimited_nofile",
				Message: fmt.Sprintf("Service '%s' has unlimited nofile ulimit; risk of FD exhaustion affecting the host", svc.Name),
			})
		} else if ul.Hard > excessiveNofileThreshold {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "fd_excessive_nofile",
				Message: fmt.Sprintf("Service '%s' has nofile hard limit %d (>%d); may exhaust host file descriptors", svc.Name, ul.Hard, excessiveNofileThreshold),
			})
		}
	} else if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "fd_no_nofile_limit",
			Message: fmt.Sprintf("Service '%s' is privileged without nofile ulimit; inherits host FD limits", svc.Name),
		})
	}

	for _, v := range svc.Volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "/dev/fd") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fd_dev_fd_mount",
				Message: fmt.Sprintf("Service '%s' mounts /dev/fd from host: %s; allows FD passing between container and host", svc.Name, v),
			})
		}
		if strings.Contains(lower, "/proc/self/fd") || strings.Contains(lower, "/proc/1/fd") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fd_proc_fd_mount",
				Message: fmt.Sprintf("Service '%s' mounts proc fd directory: %s; exposes process file descriptors", svc.Name, v),
			})
		}
		if strings.HasSuffix(lower, ".sock") || strings.HasSuffix(lower, ".socket") || strings.Contains(lower, "/var/run/docker.sock") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fd_socket_mount",
				Message: fmt.Sprintf("Service '%s' mounts a socket file: %s; socket FD accessible to container processes", svc.Name, v),
			})
		}
	}

	for _, d := range svc.Devices {
		lower := strings.ToLower(d)
		if strings.Contains(lower, "/dev/fd") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "fd_dev_fd_mount",
				Message: fmt.Sprintf("Service '%s' maps /dev/fd device: %s", svc.Name, d),
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
			case "fd_excessive_nofile":
				s.ExcessiveNofile++
			case "fd_unlimited_nofile":
				s.UnlimitedNofile++
			case "fd_dev_fd_mount":
				s.DevFdMount++
			case "fd_proc_fd_mount":
				s.ProcFdMount++
			case "fd_socket_mount":
				s.SocketMount++
			case "fd_no_nofile_limit":
				s.NoNofileLimit++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "File Descriptor Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Excessive nofile:      %d\n", r.Summary.ExcessiveNofile)
	fmt.Fprintf(&b, "  Unlimited nofile:      %d\n", r.Summary.UnlimitedNofile)
	fmt.Fprintf(&b, "  /dev/fd mount:         %d\n", r.Summary.DevFdMount)
	fmt.Fprintf(&b, "  /proc/*/fd mount:      %d\n", r.Summary.ProcFdMount)
	fmt.Fprintf(&b, "  Socket mount:          %d\n", r.Summary.SocketMount)
	fmt.Fprintf(&b, "  No nofile limit:       %d\n\n", r.Summary.NoNofileLimit)
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
