package cpupin

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
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Pinned   bool      `json:"pinned"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	PinnedServices int `json:"pinned_services"`
	Contentions    int `json:"contentions"`
	TotalFindings  int `json:"total_findings"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	var allServices []serviceInfo
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
			if svc.CpusetCpus != "" {
				allServices = append(allServices, serviceInfo{
					name:   svc.Name,
					file:   cf.Path,
					cpuset: svc.CpusetCpus,
				})
			}
		}
	}
	contentionFindings := detectContention(allServices)
	for i := range r.Services {
		for _, cf := range contentionFindings {
			if cf.service == r.Services[i].Service {
				r.Services[i].Findings = append(r.Services[i].Findings, cf.finding)
			}
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

type serviceInfo struct {
	name   string
	file   string
	cpuset string
}

type contentionFinding struct {
	service string
	finding Finding
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
		Pinned:  svc.CpusetCpus != "",
	}

	if svc.CpusetCpus != "" {
		cpus := parseCpuSet(svc.CpusetCpus)
		if len(cpus) == 1 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "cpu_pin_single_core",
				Message: fmt.Sprintf("Service '%s' pinned to single CPU %d; no failover if that core is busy", svc.Name, cpus[0]),
			})
		}
		for _, cpu := range cpus {
			if cpu > 63 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "cpu_pin_high_cpu_id",
					Message: fmt.Sprintf("Service '%s' references CPU %d; verify host has that many cores", svc.Name, cpu),
				})
				break
			}
		}
	}

	if svc.CpusetMems != "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "cpu_pin_numa_mem",
			Message: fmt.Sprintf("Service '%s' pins NUMA memory nodes to '%s'; misconfiguration causes allocation failures", svc.Name, svc.CpusetMems),
		})
	}

	if svc.CpuShares > 0 && svc.CpuShares < 2 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cpu_pin_low_shares",
			Message: fmt.Sprintf("Service '%s' has cpu_shares=%d; effectively starved under contention", svc.Name, svc.CpuShares),
		})
	}
	if svc.CpuShares >= 4096 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cpu_pin_high_shares",
			Message: fmt.Sprintf("Service '%s' has cpu_shares=%d; may monopolize CPU under contention", svc.Name, svc.CpuShares),
		})
	}

	return sr
}

func detectContention(services []serviceInfo) []contentionFinding {
	var findings []contentionFinding
	for i := 0; i < len(services); i++ {
		cpusI := parseCpuSet(services[i].cpuset)
		setI := make(map[int]bool, len(cpusI))
		for _, c := range cpusI {
			setI[c] = true
		}
		for j := i + 1; j < len(services); j++ {
			cpusJ := parseCpuSet(services[j].cpuset)
			var overlap []int
			for _, c := range cpusJ {
				if setI[c] {
					overlap = append(overlap, c)
				}
			}
			if len(overlap) > 0 {
				msg := fmt.Sprintf("Services '%s' and '%s' share pinned CPUs %v; potential contention",
					services[i].name, services[j].name, overlap)
				findings = append(findings, contentionFinding{
					service: services[i].name,
					finding: Finding{Level: "high", Rule: "cpu_pin_contention", Message: msg},
				})
				findings = append(findings, contentionFinding{
					service: services[j].name,
					finding: Finding{Level: "high", Rule: "cpu_pin_contention", Message: msg},
				})
			}
		}
	}
	return findings
}

func parseCpuSet(s string) []int {
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 == nil && err2 == nil && lo <= hi {
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if sr.Pinned {
			s.PinnedServices++
		}
		for _, f := range sr.Findings {
			s.TotalFindings++
			if f.Rule == "cpu_pin_contention" {
				s.Contentions++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CPU Pinning Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Pinned services: %d\n", r.Summary.PinnedServices)
	fmt.Fprintf(&b, "  Contentions:     %d\n\n", r.Summary.Contentions)
	for _, sr := range r.Services {
		pinLabel := "no"
		if sr.Pinned {
			pinLabel = "yes"
		}
		fmt.Fprintf(&b, "  %-30s pinned: %s\n", sr.Service, pinLabel)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
