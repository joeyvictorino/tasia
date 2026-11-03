package portrange

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
	WideRange        int `json:"wide_range"`
	OverlappingPorts int `json:"overlapping_ports"`
	HighPortCount    int `json:"high_port_count"`
	EphemeralRange   int `json:"ephemeral_range"`
	DuplicateExpose  int `json:"duplicate_expose"`
	SensitivePort    int `json:"sensitive_port"`
}

var sensitivePortNumbers = map[int]string{
	22: "SSH", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
	5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	2379: "etcd", 2380: "etcd-peer", 9200: "Elasticsearch",
	5672: "RabbitMQ", 11211: "Memcached",
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	allPorts := map[int]string{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, allPorts)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, allPorts map[int]string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	portCount := len(svc.Ports)
	if portCount > 10 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "port_high_count",
			Message: fmt.Sprintf("Service '%s' exposes %d ports; excessive port exposure increases attack surface significantly", svc.Name, portCount),
		})
	}

	for _, p := range svc.Ports {
		hostPort := p.HostPort
		containerPort := p.TargetPort

		if hostPort > 0 {
			if prev, ok := allPorts[hostPort]; ok && prev != svc.Name {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "port_overlapping",
					Message: fmt.Sprintf("Service '%s' host port %d conflicts with service '%s'; only one service can bind a host port", svc.Name, hostPort, prev),
				})
			}
			allPorts[hostPort] = svc.Name
		}

		if hostPort >= 49152 && hostPort <= 65535 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "port_ephemeral_range",
				Message: fmt.Sprintf("Service '%s' uses ephemeral port %d; this range (49152-65535) is reserved for dynamic/temporary connections and may conflict with OS port allocation", svc.Name, hostPort),
			})
		}

		checkPort := containerPort
		if hostPort > 0 {
			checkPort = hostPort
		}
		if name, ok := sensitivePortNumbers[checkPort]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "port_sensitive",
				Message: fmt.Sprintf("Service '%s' exposes %s port %d; database and infrastructure ports should not be exposed to the host without network restrictions", svc.Name, name, checkPort),
			})
		}

		if hasWideRange(p.Raw) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "port_wide_range",
				Message: fmt.Sprintf("Service '%s' maps a wide port range (%s); this exposes many ports and increases attack surface", svc.Name, p.Raw),
			})
		}
	}

	seen := map[int]bool{}
	for _, p := range svc.Ports {
		if p.HostPort > 0 {
			if seen[p.HostPort] {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "port_duplicate_expose",
					Message: fmt.Sprintf("Service '%s' exposes host port %d multiple times; may indicate misconfiguration", svc.Name, p.HostPort),
				})
			}
			seen[p.HostPort] = true
		}
	}

	return sr
}

func hasWideRange(raw string) bool {
	parts := strings.Split(raw, ":")
	for _, part := range parts {
		clean := strings.TrimSuffix(part, "/udp")
		clean = strings.TrimSuffix(clean, "/tcp")
		if strings.Contains(clean, "-") {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "port_wide_range":
				s.WideRange++
			case "port_overlapping":
				s.OverlappingPorts++
			case "port_high_count":
				s.HighPortCount++
			case "port_ephemeral_range":
				s.EphemeralRange++
			case "port_duplicate_expose":
				s.DuplicateExpose++
			case "port_sensitive":
				s.SensitivePort++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Port Range Exposure Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Wide port ranges:         %d\n", r.Summary.WideRange)
	fmt.Fprintf(&b, "  Overlapping ports:        %d\n", r.Summary.OverlappingPorts)
	fmt.Fprintf(&b, "  High port count:          %d\n", r.Summary.HighPortCount)
	fmt.Fprintf(&b, "  Ephemeral range use:      %d\n", r.Summary.EphemeralRange)
	fmt.Fprintf(&b, "  Duplicate expose:         %d\n", r.Summary.DuplicateExpose)
	fmt.Fprintf(&b, "  Sensitive port exposed:   %d\n\n", r.Summary.SensitivePort)
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
