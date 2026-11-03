package swaplimit

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
	UnlimitedSwap    int `json:"unlimited_swap"`
	SwapExceedsMemory int `json:"swap_exceeds_memory"`
	NoMemLimit       int `json:"no_mem_limit"`
	NoSwapLimit      int `json:"no_swap_limit"`
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

	hasMem := svc.MemLimit != ""
	hasSwap := svc.MemswapLimit != ""

	if hasMem && !hasSwap {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "swaplimit_no_swap_limit",
			Message: fmt.Sprintf("Service '%s' has mem_limit (%s) but no memswap_limit; swap usage is unconstrained relative to memory", svc.Name, svc.MemLimit),
		})
	}

	if !hasMem && !hasSwap {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "swaplimit_no_mem_limit",
			Message: fmt.Sprintf("Service '%s' has no memory or swap limits; can consume all host memory and swap", svc.Name),
		})
	}

	if hasSwap {
		swapLower := strings.ToLower(svc.MemswapLimit)
		if swapLower == "-1" || swapLower == "unlimited" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "swaplimit_unlimited",
				Message: fmt.Sprintf("Service '%s' has memswap_limit: %s (unlimited swap); can exhaust host swap space", svc.Name, svc.MemswapLimit),
			})
		}
	}

	if hasMem && hasSwap {
		memBytes := parseSize(svc.MemLimit)
		swapBytes := parseSize(svc.MemswapLimit)
		if memBytes > 0 && swapBytes > memBytes*2 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "swaplimit_exceeds_memory",
				Message: fmt.Sprintf("Service '%s' memswap_limit (%s) is more than 2x mem_limit (%s); excessive swap can hide memory issues", svc.Name, svc.MemswapLimit, svc.MemLimit),
			})
		}
	}

	if svc.Privileged && !hasMem && !hasSwap {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "swaplimit_privileged_no_limit",
			Message: fmt.Sprintf("Service '%s' is privileged with no memory/swap limits; can consume all host resources", svc.Name),
		})
	}

	return sr
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-1" || strings.ToLower(s) == "unlimited" {
		return 0
	}
	s = strings.ToLower(s)
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
			case "swaplimit_unlimited":
				s.UnlimitedSwap++
			case "swaplimit_exceeds_memory":
				s.SwapExceedsMemory++
			case "swaplimit_no_mem_limit":
				s.NoMemLimit++
			case "swaplimit_no_swap_limit":
				s.NoSwapLimit++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Swap Limit Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unlimited swap:       %d\n", r.Summary.UnlimitedSwap)
	fmt.Fprintf(&b, "  Swap exceeds memory:  %d\n", r.Summary.SwapExceedsMemory)
	fmt.Fprintf(&b, "  No memory limit:      %d\n", r.Summary.NoMemLimit)
	fmt.Fprintf(&b, "  No swap limit:        %d\n\n", r.Summary.NoSwapLimit)
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
