package fdlimit

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
	MissingNofile    int `json:"missing_nofile"`
	HighFdLimit      int `json:"high_fd_limit"`
	HostPidFdLeak    int `json:"host_pid_fd_leak"`
	SocketExhaustion int `json:"socket_exhaustion"`
	PipeAccumulation int `json:"pipe_accumulation"`
	PrivilegedFd     int `json:"privileged_fd"`
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

	nofileSet := false
	if len(svc.Ulimits) > 0 {
		if uv, ok := svc.Ulimits["nofile"]; ok {
			nofileSet = true
			if uv.Hard > 1000000 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "fdlimit_high_nofile",
					Message: fmt.Sprintf("Service '%s' sets nofile hard limit to %d (>1M); excessive fd limits can enable resource exhaustion attacks", svc.Name, uv.Hard),
				})
			}
			if uv.Soft > uv.Hard && uv.Hard > 0 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "fdlimit_soft_exceeds_hard",
					Message: fmt.Sprintf("Service '%s' has nofile soft limit (%d) exceeding hard limit (%d)", svc.Name, uv.Soft, uv.Hard),
				})
			}
		}
		if uv, ok := svc.Ulimits["nproc"]; ok {
			if uv.Hard > 100000 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "fdlimit_high_nproc",
					Message: fmt.Sprintf("Service '%s' sets nproc hard limit to %d (>100k); may allow fork bombs or process exhaustion", svc.Name, uv.Hard),
				})
			}
		}
	}

	if !nofileSet {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "fdlimit_missing_nofile",
			Message: fmt.Sprintf("Service '%s' has no ulimit nofile set; inherits host default which may be too permissive", svc.Name),
		})
	}

	if svc.PidMode == "host" && !nofileSet {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "fdlimit_host_pid_fd_leak",
			Message: fmt.Sprintf("Service '%s' uses host PID namespace without fd limits; container processes share host fd table visibility", svc.Name),
		})
	}

	hasSocketPort := len(svc.Ports) > 5
	if hasSocketPort && !nofileSet {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "fdlimit_socket_exhaustion",
			Message: fmt.Sprintf("Service '%s' exposes %d ports without fd limits; high port count increases socket descriptor exhaustion risk", svc.Name, len(svc.Ports)),
		})
	}

	for _, vol := range svc.Volumes {
		lower := strings.ToLower(vol)
		if strings.Contains(lower, "/proc") || strings.Contains(lower, "named_pipe") || strings.Contains(lower, "fifo") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "fdlimit_pipe_accumulation",
				Message: fmt.Sprintf("Service '%s' mounts pipe/proc-related path '%s'; pipe descriptors can accumulate without limits", svc.Name, vol),
			})
			break
		}
	}

	if svc.Privileged && !nofileSet {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "fdlimit_privileged_no_limit",
			Message: fmt.Sprintf("Service '%s' is privileged without fd limits; can exhaust host file descriptors", svc.Name),
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
			case "fdlimit_missing_nofile":
				s.MissingNofile++
			case "fdlimit_high_nofile":
				s.HighFdLimit++
			case "fdlimit_host_pid_fd_leak":
				s.HostPidFdLeak++
			case "fdlimit_socket_exhaustion":
				s.SocketExhaustion++
			case "fdlimit_pipe_accumulation":
				s.PipeAccumulation++
			case "fdlimit_privileged_no_limit":
				s.PrivilegedFd++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "File Descriptor Limit Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing nofile:         %d\n", r.Summary.MissingNofile)
	fmt.Fprintf(&b, "  High fd limit (>1M):    %d\n", r.Summary.HighFdLimit)
	fmt.Fprintf(&b, "  Host PID fd leak:       %d\n", r.Summary.HostPidFdLeak)
	fmt.Fprintf(&b, "  Socket exhaustion risk: %d\n", r.Summary.SocketExhaustion)
	fmt.Fprintf(&b, "  Pipe accumulation:      %d\n", r.Summary.PipeAccumulation)
	fmt.Fprintf(&b, "  Privileged no limit:    %d\n\n", r.Summary.PrivilegedFd)
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
