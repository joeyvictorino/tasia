package pipeclean

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
	WritableFifoMounts  int `json:"writable_fifo_mounts"`
	SharedPipePaths     int `json:"shared_pipe_paths"`
	WorldWritablePipes  int `json:"world_writable_pipes"`
	UnsafeMkfifoUsage   int `json:"unsafe_mkfifo_usage"`
	PipeEscapeRisks     int `json:"pipe_escape_risks"`
	MissingPipeIsolation int `json:"missing_pipe_isolation"`
}

var fifoPaths = []string{
	"/tmp", "/var/tmp", "/dev/shm",
	"/run", "/var/run",
	"/dev/mqueue",
}

var pipeIndicators = []string{
	"mkfifo", "mknod", "named_pipe", "fifo",
}

var dangerousPipeEnvKeys = []string{
	"PIPE_PATH", "FIFO_PATH", "NAMED_PIPE",
	"IPC_PIPE", "COMM_PIPE", "MSG_PIPE",
}

func isFifoPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, p := range fifoPaths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func containerPath(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) >= 2 {
		return parts[1]
	}
	return parts[0]
}

func hostPath(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	return parts[0]
}

func isWritableMount(volumeSpec string) bool {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) < 3 {
		return true
	}
	return !strings.Contains(strings.ToLower(parts[2]), "ro")
}

func hasPipeIndicator(s string) bool {
	lower := strings.ToLower(s)
	for _, ind := range pipeIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string, allServices []compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, v := range svc.Volumes {
		cp := containerPath(v)
		hp := hostPath(v)
		writable := isWritableMount(v)

		if isFifoPath(cp) && writable {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "writable_fifo_mount",
				Message: fmt.Sprintf("Service '%s' mounts writable path '%s' at FIFO-capable location '%s'; processes can create named pipes to communicate outside container boundaries", svc.Name, hp, cp),
			})
		}

		if writable && hasPipeIndicator(v) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "pipe_escape_risk",
				Message: fmt.Sprintf("Service '%s' volume '%s' appears to reference a named pipe; writable pipe mounts can be used for container escape via IPC", svc.Name, v),
			})
		}

		if writable && isFifoPath(hp) {
			for _, other := range allServices {
				if other.Name == svc.Name {
					continue
				}
				for _, ov := range other.Volumes {
					ocp := containerPath(ov)
					if ocp == cp || strings.HasPrefix(ocp, cp+"/") || strings.HasPrefix(cp, ocp+"/") {
						sr.Findings = append(sr.Findings, Finding{
							Level:   "medium",
							Rule:    "shared_pipe_path",
							Message: fmt.Sprintf("Services '%s' and '%s' share writable mount path '%s'; named pipes in shared paths enable uncontrolled IPC", svc.Name, other.Name, cp),
						})
						break
					}
				}
			}
		}
	}

	for _, cmd := range svc.Command {
		if hasPipeIndicator(cmd) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "unsafe_mkfifo_usage",
				Message: fmt.Sprintf("Service '%s' command references pipe creation ('%s'); named pipes should be created with restrictive permissions", svc.Name, cmd),
			})
		}
	}
	for _, ep := range svc.Entrypoint {
		if hasPipeIndicator(ep) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "unsafe_mkfifo_usage",
				Message: fmt.Sprintf("Service '%s' entrypoint references pipe creation ('%s'); named pipes should be created with restrictive permissions", svc.Name, ep),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := parts[1]
		for _, dk := range dangerousPipeEnvKeys {
			if strings.Contains(key, dk) {
				if isFifoPath(val) || hasPipeIndicator(val) {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "medium",
						Rule:    "world_writable_pipe",
						Message: fmt.Sprintf("Service '%s' env var '%s' points to pipe path '%s'; ensure restrictive permissions on the FIFO", svc.Name, parts[0], val),
					})
				}
			}
		}
	}

	hasWritableFifo := false
	for _, v := range svc.Volumes {
		if isFifoPath(containerPath(v)) && isWritableMount(v) {
			hasWritableFifo = true
			break
		}
	}
	if hasWritableFifo && !svc.ReadOnly {
		hasCap := false
		for _, c := range svc.CapAdd {
			if strings.ToUpper(c) == "MKNOD" || strings.ToUpper(c) == "SYS_ADMIN" || strings.ToUpper(c) == "ALL" {
				hasCap = true
				break
			}
		}
		if hasCap {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "missing_pipe_isolation",
				Message: fmt.Sprintf("Service '%s' has writable FIFO paths and MKNOD/SYS_ADMIN capability without read-only rootfs; consider restricting pipe creation", svc.Name),
			})
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, cf.Services)
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
			case "writable_fifo_mount":
				s.WritableFifoMounts++
			case "shared_pipe_path":
				s.SharedPipePaths++
			case "world_writable_pipe":
				s.WorldWritablePipes++
			case "unsafe_mkfifo_usage":
				s.UnsafeMkfifoUsage++
			case "pipe_escape_risk":
				s.PipeEscapeRisks++
			case "missing_pipe_isolation":
				s.MissingPipeIsolation++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Named Pipe / FIFO Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Writable FIFO mounts:    %d\n", r.Summary.WritableFifoMounts)
	fmt.Fprintf(&b, "  Shared pipe paths:       %d\n", r.Summary.SharedPipePaths)
	fmt.Fprintf(&b, "  World-writable pipes:    %d\n", r.Summary.WorldWritablePipes)
	fmt.Fprintf(&b, "  Unsafe mkfifo usage:     %d\n", r.Summary.UnsafeMkfifoUsage)
	fmt.Fprintf(&b, "  Pipe escape risks:       %d\n", r.Summary.PipeEscapeRisks)
	fmt.Fprintf(&b, "  Missing pipe isolation:  %d\n\n", r.Summary.MissingPipeIsolation)
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
