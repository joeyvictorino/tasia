package swapusage

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
	UnlimitedSwap       int `json:"unlimited_swap"`
	SwapNoMemLimit      int `json:"swap_no_mem_limit"`
	HighSwappiness      int `json:"high_swappiness"`
	SwapEqualsMem       int `json:"swap_equals_mem"`
	SwapEnvExposed      int `json:"swap_env_exposed"`
	SwapPrivileged      int `json:"swap_privileged"`
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

	hasMemLimit := svc.MemLimit != ""
	hasSwapLimit := svc.MemswapLimit != ""

	if hasSwapLimit && (svc.MemswapLimit == "-1" || svc.MemswapLimit == "0") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "swap_unlimited",
			Message: fmt.Sprintf("Service '%s' has unlimited swap (memswap_limit=%s); can exhaust host swap space", svc.Name, svc.MemswapLimit),
		})
	}

	if hasSwapLimit && !hasMemLimit {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "swap_no_mem_limit",
			Message: fmt.Sprintf("Service '%s' sets memswap_limit without mem_limit; effective swap constraint is ambiguous", svc.Name),
		})
	}

	if swappiness, ok := svc.Sysctls["vm.swappiness"]; ok {
		if swappiness == "100" || swappiness == "90" || swappiness == "80" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "swap_high_swappiness",
				Message: fmt.Sprintf("Service '%s' has high vm.swappiness=%s; aggressive swapping degrades performance and may leak memory contents to disk", svc.Name, swappiness),
			})
		}
	}

	if hasMemLimit && hasSwapLimit && svc.MemswapLimit == svc.MemLimit && svc.MemswapLimit != "-1" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "swap_equals_mem",
			Message: fmt.Sprintf("Service '%s' has memswap_limit equal to mem_limit; swap is effectively disabled (expected if intentional)", svc.Name),
		})
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := strings.ToUpper(parts[0])
			if strings.Contains(key, "SWAP") && !strings.HasPrefix(parts[1], "${") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "swap_env_exposed",
					Message: fmt.Sprintf("Service '%s' exposes swap configuration via environment variable '%s'", svc.Name, parts[0]),
				})
				break
			}
		}
	}

	if svc.Privileged && hasSwapLimit && (svc.MemswapLimit == "-1" || svc.MemswapLimit == "0") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "swap_privileged_unlimited",
			Message: fmt.Sprintf("Service '%s' is privileged with unlimited swap; can consume all host swap and destabilize the system", svc.Name),
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
			case "swap_unlimited":
				s.UnlimitedSwap++
			case "swap_no_mem_limit":
				s.SwapNoMemLimit++
			case "swap_high_swappiness":
				s.HighSwappiness++
			case "swap_equals_mem":
				s.SwapEqualsMem++
			case "swap_env_exposed":
				s.SwapEnvExposed++
			case "swap_privileged_unlimited":
				s.SwapPrivileged++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Swap Usage Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unlimited swap:        %d\n", r.Summary.UnlimitedSwap)
	fmt.Fprintf(&b, "  Swap without mem_limit: %d\n", r.Summary.SwapNoMemLimit)
	fmt.Fprintf(&b, "  High swappiness:       %d\n", r.Summary.HighSwappiness)
	fmt.Fprintf(&b, "  Swap equals mem:       %d\n", r.Summary.SwapEqualsMem)
	fmt.Fprintf(&b, "  Swap env exposed:      %d\n", r.Summary.SwapEnvExposed)
	fmt.Fprintf(&b, "  Swap privileged:       %d\n\n", r.Summary.SwapPrivileged)
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
