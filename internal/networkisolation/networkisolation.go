package networkisolation

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
	NoInternalNet    int `json:"no_internal_network"`
	WildcardBind     int `json:"wildcard_bind"`
	ExposedHighPort  int `json:"exposed_high_port"`
	MissingDNSConfig int `json:"missing_dns_config"`
	HostIPC          int `json:"host_ipc"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	hasInternal := false
	for _, cf := range c.ComposeFiles {
		for _, n := range cf.Networks {
			if n.Internal {
				hasInternal = true
				break
			}
		}
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, hasInternal)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, hasInternal bool) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "networkisolation_host_network",
			Message: fmt.Sprintf("Service '%s' uses host network mode; bypasses all Docker network isolation", svc.Name),
		})
	}

	if !hasInternal && svc.NetworkMode != "host" && svc.NetworkMode != "none" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "networkisolation_no_internal",
			Message: fmt.Sprintf("Service '%s' has no internal network defined; inter-service traffic is not isolated from external access", svc.Name),
		})
	}

	for _, pm := range svc.Ports {
		if pm.HostIP == "" || pm.HostIP == "0.0.0.0" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "networkisolation_wildcard_bind",
				Message: fmt.Sprintf("Service '%s' binds port %d to all interfaces (0.0.0.0); consider 127.0.0.1 to limit exposure", svc.Name, pm.HostPort),
			})
		}
		if pm.HostPort > 30000 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "networkisolation_high_port",
				Message: fmt.Sprintf("Service '%s' exposes high port %d on host; ephemeral-range ports can conflict with OS allocations", svc.Name, pm.HostPort),
			})
		}
	}

	if len(svc.DNS) == 0 && svc.NetworkMode != "host" && svc.NetworkMode != "none" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "networkisolation_no_dns_config",
			Message: fmt.Sprintf("Service '%s' uses default DNS; explicit dns config prevents DNS-based data exfiltration", svc.Name),
		})
	}

	if strings.ToLower(svc.IpcMode) == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "networkisolation_host_ipc",
			Message: fmt.Sprintf("Service '%s' uses host IPC namespace; shared memory segments are visible to host processes", svc.Name),
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
			case "networkisolation_host_network":
				s.HostNetwork++
			case "networkisolation_no_internal":
				s.NoInternalNet++
			case "networkisolation_wildcard_bind":
				s.WildcardBind++
			case "networkisolation_high_port":
				s.ExposedHighPort++
			case "networkisolation_no_dns_config":
				s.MissingDNSConfig++
			case "networkisolation_host_ipc":
				s.HostIPC++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Network Isolation Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host network mode:      %d\n", r.Summary.HostNetwork)
	fmt.Fprintf(&b, "  No internal network:    %d\n", r.Summary.NoInternalNet)
	fmt.Fprintf(&b, "  Wildcard bind (0.0.0.0):%d\n", r.Summary.WildcardBind)
	fmt.Fprintf(&b, "  High port exposure:     %d\n", r.Summary.ExposedHighPort)
	fmt.Fprintf(&b, "  Missing DNS config:     %d\n", r.Summary.MissingDNSConfig)
	fmt.Fprintf(&b, "  Host IPC namespace:     %d\n\n", r.Summary.HostIPC)
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
