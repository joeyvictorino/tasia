package composenet

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
	HostNetwork      int `json:"host_network"`
	NoNetworkDefined int `json:"no_network_defined"`
	DefaultBridge    int `json:"default_bridge"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		hasNetworks := len(cf.Networks) > 0
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, hasNetworks)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, hasNetworks bool) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if strings.EqualFold(svc.NetworkMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "composenet_host_network",
			Message: fmt.Sprintf("Service '%s' uses network_mode: host; this exposes all host network interfaces and ports to the container, bypassing Docker network isolation", svc.Name),
		})
	}

	if svc.NetworkMode == "" && !hasNetworks {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "composenet_no_network",
			Message: fmt.Sprintf("Service '%s' has no explicit network configuration; all services share the default bridge network with unrestricted inter-container communication", svc.Name),
		})
	}

	if strings.EqualFold(svc.NetworkMode, "bridge") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "composenet_default_bridge",
			Message: fmt.Sprintf("Service '%s' explicitly uses the default bridge network; consider using a custom network with limited scope for better isolation", svc.Name),
		})
	}

	if strings.EqualFold(svc.NetworkMode, "host") && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "composenet_host_ports_redundant",
			Message: fmt.Sprintf("Service '%s' defines port mappings with network_mode: host; port mappings are ignored in host network mode", svc.Name),
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
			case "composenet_host_network":
				s.HostNetwork++
			case "composenet_no_network":
				s.NoNetworkDefined++
			case "composenet_default_bridge":
				s.DefaultBridge++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Compose Network Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host network mode:    %d\n", r.Summary.HostNetwork)
	fmt.Fprintf(&b, "  No network defined:   %d\n", r.Summary.NoNetworkDefined)
	fmt.Fprintf(&b, "  Default bridge:       %d\n", r.Summary.DefaultBridge)
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
