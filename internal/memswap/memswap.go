package memswap

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
	Service      string    `json:"service"`
	File         string    `json:"file"`
	MemLimit     string    `json:"mem_limit"`
	MemswapLimit string    `json:"memswap_limit"`
	Findings     []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	UnlimitedSwap    int `json:"unlimited_swap"`
	SwapDisabled     int `json:"swap_disabled"`
	ExcessiveRatio   int `json:"excessive_ratio"`
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
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service:      svc.Name,
		File:         file,
		MemLimit:     svc.MemLimit,
		MemswapLimit: svc.MemswapLimit,
	}

	hasMemLimit := svc.MemLimit != ""
	hasSwapLimit := svc.MemswapLimit != ""

	if hasMemLimit && !hasSwapLimit {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "memswap_unlimited",
			Message: fmt.Sprintf("service %q has mem_limit=%s but no memswap_limit; swap is unlimited and can bypass memory constraints", svc.Name, svc.MemLimit),
		})
	}

	if hasMemLimit && hasSwapLimit && svc.MemswapLimit == svc.MemLimit {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "memswap_disabled",
			Message: fmt.Sprintf("service %q has memswap_limit equal to mem_limit; swap is effectively disabled", svc.Name),
		})
	}

	if hasMemLimit && hasSwapLimit {
		memBytes := parseSize(svc.MemLimit)
		swapBytes := parseSize(svc.MemswapLimit)
		if memBytes > 0 && swapBytes > memBytes*4 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "memswap_excessive",
				Message: fmt.Sprintf("service %q has memswap_limit %s > 4x mem_limit %s; excessive swap causes thrashing and degraded performance", svc.Name, svc.MemswapLimit, svc.MemLimit),
			})
		}
	}

	if svc.Privileged && hasMemLimit && !hasSwapLimit {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "memswap_privileged_unlimited",
			Message: fmt.Sprintf("privileged service %q has mem_limit but no swap limit; attacker can exhaust host swap space", svc.Name),
		})
	}

	if hasSwapLimit && svc.MemswapLimit == "-1" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "memswap_explicit_unlimited",
			Message: fmt.Sprintf("service %q has memswap_limit: -1 (explicitly unlimited swap); this disables swap accounting", svc.Name),
		})
	}

	return sr
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "-1" {
		return 0
	}
	multiplier := int64(1)
	if strings.HasSuffix(s, "g") {
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "m") {
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "k") {
		multiplier = 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "b") {
		s = s[:len(s)-1]
	}
	var val int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			val = val*10 + int64(c-'0')
		}
	}
	return val * multiplier
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			switch f.Rule {
			case "memswap_unlimited", "memswap_explicit_unlimited", "memswap_privileged_unlimited":
				s.UnlimitedSwap++
			case "memswap_disabled":
				s.SwapDisabled++
			case "memswap_excessive":
				s.ExcessiveRatio++
			}
		}
		s.TotalFindings += len(sr.Findings)
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Memory Swap Limit Analysis: %s\n\n", r.Path)
	for _, sr := range r.Services {
		limits := ""
		if sr.MemLimit != "" {
			limits += fmt.Sprintf(" mem_limit=%s", sr.MemLimit)
		}
		if sr.MemswapLimit != "" {
			limits += fmt.Sprintf(" memswap_limit=%s", sr.MemswapLimit)
		}
		if limits == "" {
			limits = " (no memory limits)"
		}
		fmt.Fprintf(&b, "  %s%s\n", sr.Service, limits)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s – %s\n", f.Level, f.Rule, f.Message)
		}
	}
	fmt.Fprintf(&b, "\n  Summary: %d services, %d unlimited swap, %d swap disabled, %d excessive ratio, %d findings\n",
		r.Summary.TotalServices, r.Summary.UnlimitedSwap, r.Summary.SwapDisabled, r.Summary.ExcessiveRatio, r.Summary.TotalFindings)
	return b.String()
}
