package netalias

import (
	"encoding/json"
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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	HostNetwork       int `json:"host_network"`
	SharedDefault     int `json:"shared_default"`
	ContainerNetwork  int `json:"container_network"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, cf compose.File) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: cf.Path}

	if svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "network_mode_host",
			Message: fmt.Sprintf("Service '%s' uses network_mode: host; shares the host network namespace and can see all host traffic", svc.Name),
		})
	}

	if strings.HasPrefix(svc.NetworkMode, "container:") {
		target := strings.TrimPrefix(svc.NetworkMode, "container:")
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "network_mode_container",
			Message: fmt.Sprintf("Service '%s' shares network namespace with container '%s'; network isolation between these containers is eliminated", svc.Name, target),
		})
	}

	if svc.NetworkMode == "" && len(cf.Networks) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "default_network_shared",
			Message: fmt.Sprintf("Service '%s' uses the default bridge network with no custom networks defined; all services share one flat network", svc.Name),
		})
	}

	hasNonInternal := false
	for name, net := range cf.Networks {
		if !net.Internal {
			hasNonInternal = true
			_ = name
		}
	}
	if hasNonInternal && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "exposed_on_non_internal",
			Message: fmt.Sprintf("Service '%s' publishes ports on a non-internal network; consider using internal networks to limit external exposure", svc.Name),
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
			case "network_mode_host":
				s.HostNetwork++
			case "default_network_shared":
				s.SharedDefault++
			case "network_mode_container":
				s.ContainerNetwork++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Network Alias Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host network mode:     %d\n", r.Summary.HostNetwork)
	fmt.Fprintf(&b, "  Shared default net:    %d\n", r.Summary.SharedDefault)
	fmt.Fprintf(&b, "  Container net share:   %d\n\n", r.Summary.ContainerNetwork)
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

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
