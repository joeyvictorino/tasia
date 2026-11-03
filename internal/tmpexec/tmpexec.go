package tmpexec

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
	TmpExecMounts       int `json:"tmp_exec_mounts"`
	LargeTmpfs          int `json:"large_tmpfs"`
	WorldWritableTmp    int `json:"world_writable_tmp"`
	NoTmpIsolation      int `json:"no_tmp_isolation"`
	PrivilegedTmpAccess int `json:"privileged_tmp_access"`
	HostTmpMount        int `json:"host_tmp_mount"`
}

const (
	largeTmpfsThreshold int64 = 1024 * 1024 * 1024 // 1 GiB
)

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

	hasTmpVolume := false
	hasTmpfs := false

	for _, v := range svc.Volumes {
		vLower := strings.ToLower(v)
		if strings.Contains(vLower, "/tmp") && !strings.Contains(vLower, "noexec") {
			parts := strings.Split(v, ":")
			if len(parts) >= 2 {
				src := strings.ToLower(parts[0])
				if src == "/tmp" || strings.HasPrefix(src, "/tmp/") {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "tmp_host_mount",
						Message: fmt.Sprintf("Service '%s' mounts host /tmp (%s); host temp files accessible to container", svc.Name, v),
					})
					hasTmpVolume = true
				}
			}
		}
	}

	for _, t := range svc.Tmpfs {
		tLower := strings.ToLower(t)
		hasTmpfs = true

		if strings.Contains(tLower, "/tmp") && !strings.Contains(tLower, "noexec") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "tmp_exec_mount",
				Message: fmt.Sprintf("Service '%s' has tmpfs at /tmp without noexec; code can be written and executed in temp directory", svc.Name),
			})
		}

		if strings.Contains(tLower, "size=") {
			size := extractTmpfsSize(t)
			if size > largeTmpfsThreshold {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "tmp_large_tmpfs",
					Message: fmt.Sprintf("Service '%s' has tmpfs larger than 1g; large temp filesystems increase attack surface", svc.Name),
				})
			}
		}
	}

	if !hasTmpVolume && !hasTmpfs && !svc.ReadOnly {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "tmp_no_isolation",
			Message: fmt.Sprintf("Service '%s' has no explicit temp directory isolation; writable container filesystem includes /tmp", svc.Name),
		})
	}

	if svc.Privileged {
		for _, v := range svc.Volumes {
			if strings.Contains(strings.ToLower(v), "/tmp") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "tmp_privileged_access",
					Message: fmt.Sprintf("Service '%s' is privileged with /tmp access; can execute arbitrary code with full host privileges", svc.Name),
				})
				break
			}
		}
		for _, t := range svc.Tmpfs {
			if strings.Contains(strings.ToLower(t), "/tmp") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "tmp_privileged_access",
					Message: fmt.Sprintf("Service '%s' is privileged with tmpfs /tmp; can execute arbitrary code with full host privileges", svc.Name),
				})
				break
			}
		}
	}

	return sr
}

func extractTmpfsSize(s string) int64 {
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "size=")
	if idx < 0 {
		return 0
	}
	rest := lower[idx+5:]
	end := strings.IndexAny(rest, ",: ")
	if end > 0 {
		rest = rest[:end]
	}
	return parseSize(rest)
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "g"):
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "k"):
		multiplier = 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "b"):
		s = s[:len(s)-1]
	}
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n * multiplier
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "tmp_exec_mount":
				s.TmpExecMounts++
			case "tmp_large_tmpfs":
				s.LargeTmpfs++
			case "tmp_no_isolation":
				s.NoTmpIsolation++
			case "tmp_privileged_access":
				s.PrivilegedTmpAccess++
			case "tmp_host_mount":
				s.HostTmpMount++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Temp Directory Execution Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Tmp exec mounts:      %d\n", r.Summary.TmpExecMounts)
	fmt.Fprintf(&b, "  Large tmpfs:          %d\n", r.Summary.LargeTmpfs)
	fmt.Fprintf(&b, "  No tmp isolation:     %d\n", r.Summary.NoTmpIsolation)
	fmt.Fprintf(&b, "  Privileged tmp:       %d\n", r.Summary.PrivilegedTmpAccess)
	fmt.Fprintf(&b, "  Host /tmp mount:      %d\n\n", r.Summary.HostTmpMount)
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
