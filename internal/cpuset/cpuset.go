package cpuset

import (
	"fmt"
	"strconv"
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
	Service    string    `json:"service"`
	File       string    `json:"file"`
	CpusetCpus string   `json:"cpuset_cpus"`
	CpusetMems string   `json:"cpuset_mems"`
	Findings   []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	NoCpuset         int `json:"no_cpuset"`
	OverlappingCpus  int `json:"overlapping_cpus"`
	WidePinning      int `json:"wide_pinning"`
	TotalFindings    int `json:"total_findings"`
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
	checkOverlaps(&r)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service:    svc.Name,
		File:       file,
		CpusetCpus: svc.CpusetCpus,
		CpusetMems: svc.CpusetMems,
	}

	if svc.CpusetCpus == "" && svc.CpusetMems == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "cpuset_none",
			Message: fmt.Sprintf("service %q has no cpuset constraints; container can use all CPUs", svc.Name),
		})
	}

	if svc.CpusetCpus != "" {
		cpus := parseCpuList(svc.CpusetCpus)
		if len(cpus) > 8 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "cpuset_wide_pin",
				Message: fmt.Sprintf("service %q pinned to %d CPUs (%s); wide pinning reduces isolation", svc.Name, len(cpus), svc.CpusetCpus),
			})
		}
		if isPrivilegedWorkload(svc) && len(cpus) > 4 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "cpuset_privileged_wide",
				Message: fmt.Sprintf("privileged service %q pinned to %d CPUs; limit privileged containers to fewer CPUs", svc.Name, len(cpus)),
			})
		}
	}

	if svc.CpusetMems != "" {
		nodes := parseCpuList(svc.CpusetMems)
		if len(nodes) > 4 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "info",
				Rule:    "cpuset_wide_mems",
				Message: fmt.Sprintf("service %q pinned to %d NUMA nodes (%s); consider narrowing for better locality", svc.Name, len(nodes), svc.CpusetMems),
			})
		}
	}

	return sr
}

func parseCpuList(spec string) []int {
	var result []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.Index(part, "-"); idx >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(part[:idx]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(part[idx+1:]))
			if err1 == nil && err2 == nil && hi >= lo {
				for i := lo; i <= hi; i++ {
					result = append(result, i)
				}
			}
		} else {
			if n, err := strconv.Atoi(part); err == nil {
				result = append(result, n)
			}
		}
	}
	return result
}

func isPrivilegedWorkload(svc compose.Service) bool {
	return svc.Privileged
}

func checkOverlaps(r *Report) {
	cpuMap := make(map[int][]string)
	for _, sr := range r.Services {
		if sr.CpusetCpus == "" {
			continue
		}
		cpus := parseCpuList(sr.CpusetCpus)
		for _, cpu := range cpus {
			cpuMap[cpu] = append(cpuMap[cpu], sr.Service)
		}
	}
	seen := make(map[string]bool)
	for cpu, svcs := range cpuMap {
		if len(svcs) > 1 {
			key := strings.Join(svcs, "+")
			if !seen[key] {
				seen[key] = true
				r.Services = append(r.Services, ServiceResult{
					Findings: []Finding{{
						Level:   "medium",
						Rule:    "cpuset_overlap",
						Message: fmt.Sprintf("CPU %d shared by services %s; overlapping cpuset reduces isolation", cpu, strings.Join(svcs, ", ")),
					}},
				})
				r.Summary.OverlappingCpus++
			}
		}
	}
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if sr.CpusetCpus == "" && sr.CpusetMems == "" && sr.Service != "" {
			s.NoCpuset++
		}
		for _, f := range sr.Findings {
			s.TotalFindings++
			if f.Rule == "cpuset_wide_pin" || f.Rule == "cpuset_privileged_wide" {
				s.WidePinning++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CPU Set Affinity Analysis: %s\n\n", r.Path)
	for _, sr := range r.Services {
		if sr.Service == "" {
			for _, f := range sr.Findings {
				fmt.Fprintf(&b, "  [%s] %s – %s\n", f.Level, f.Rule, f.Message)
			}
			continue
		}
		fmt.Fprintf(&b, "  %s", sr.Service)
		if sr.CpusetCpus != "" {
			fmt.Fprintf(&b, "  cpuset_cpus=%s", sr.CpusetCpus)
		}
		if sr.CpusetMems != "" {
			fmt.Fprintf(&b, "  cpuset_mems=%s", sr.CpusetMems)
		}
		b.WriteString("\n")
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s – %s\n", f.Level, f.Rule, f.Message)
		}
	}
	fmt.Fprintf(&b, "\n  Summary: %d services, %d unconstrained, %d overlapping, %d wide-pinned, %d findings\n",
		r.Summary.TotalServices, r.Summary.NoCpuset, r.Summary.OverlappingCpus, r.Summary.WidePinning, r.Summary.TotalFindings)
	return b.String()
}
