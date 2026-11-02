package bindprop

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

type MountInfo struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Propagation string `json:"propagation"`
	ReadOnly    bool   `json:"read_only"`
}

type ServiceResult struct {
	Service  string      `json:"service"`
	File     string      `json:"file"`
	Mounts   []MountInfo `json:"mounts"`
	Findings []Finding   `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	TotalMounts     int `json:"total_mounts"`
	SharedMounts    int `json:"shared_mounts"`
	UnsafePropagation int `json:"unsafe_propagation"`
	TotalFindings   int `json:"total_findings"`
}

var propagationModes = map[string]bool{
	"rprivate": true, "private": true,
	"rshared": true, "shared": true,
	"rslave": true, "slave": true,
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
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
	}

	for _, vol := range svc.Volumes {
		mi := parseMount(vol)
		if mi == nil {
			continue
		}
		sr.Mounts = append(sr.Mounts, *mi)

		if mi.Propagation == "rshared" || mi.Propagation == "shared" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "bindprop_shared_mount",
				Message: fmt.Sprintf("Service '%s' mount '%s' uses '%s' propagation; container mounts leak to host and siblings", svc.Name, mi.Target, mi.Propagation),
			})
		}

		if mi.Propagation == "rslave" || mi.Propagation == "slave" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "bindprop_slave_mount",
				Message: fmt.Sprintf("Service '%s' mount '%s' uses '%s' propagation; host mounts propagate into container", svc.Name, mi.Target, mi.Propagation),
			})
		}

		if !mi.ReadOnly && (mi.Propagation == "rshared" || mi.Propagation == "shared") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "bindprop_shared_rw",
				Message: fmt.Sprintf("Service '%s' mount '%s' is shared AND writable; container can mount filesystems visible to the host", svc.Name, mi.Target),
			})
		}

		if mi.Propagation == "" && isBindMount(mi.Source) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "bindprop_default_propagation",
				Message: fmt.Sprintf("Service '%s' bind mount '%s' has no explicit propagation mode; defaults to rprivate", svc.Name, mi.Target),
			})
		}

		if mi.Propagation == "private" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "bindprop_non_recursive",
				Message: fmt.Sprintf("Service '%s' mount '%s' uses 'private' (non-recursive); nested mounts may be invisible—consider 'rprivate'", svc.Name, mi.Target),
			})
		}
	}

	return sr
}

func parseMount(vol string) *MountInfo {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return nil
	}
	mi := &MountInfo{
		Source: parts[0],
		Target: parts[1],
	}
	if len(parts) >= 3 {
		opts := strings.Split(parts[2], ",")
		for _, opt := range opts {
			opt = strings.TrimSpace(opt)
			if opt == "ro" {
				mi.ReadOnly = true
			}
			if propagationModes[opt] {
				mi.Propagation = opt
			}
		}
	}
	return mi
}

func isBindMount(source string) bool {
	return strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") || strings.HasPrefix(source, "~")
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		s.TotalMounts += len(sr.Mounts)
		s.TotalFindings += len(sr.Findings)
		for _, m := range sr.Mounts {
			if m.Propagation == "rshared" || m.Propagation == "shared" {
				s.SharedMounts++
				s.UnsafePropagation++
			} else if m.Propagation == "rslave" || m.Propagation == "slave" {
				s.UnsafePropagation++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bind Mount Propagation Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Total mounts:         %d\n", r.Summary.TotalMounts)
	fmt.Fprintf(&b, "  Shared propagation:   %d\n", r.Summary.SharedMounts)
	fmt.Fprintf(&b, "  Unsafe propagation:   %d\n\n", r.Summary.UnsafePropagation)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s mounts: %d\n", sr.Service, len(sr.Mounts))
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, m := range sr.Mounts {
			prop := m.Propagation
			if prop == "" {
				prop = "(default)"
			}
			rwLabel := "rw"
			if m.ReadOnly {
				rwLabel = "ro"
			}
			fmt.Fprintf(&b, "    %s -> %s [%s, %s]\n", m.Source, m.Target, rwLabel, prop)
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
