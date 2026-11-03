package trustchain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type TrustZone string

const (
	ZoneExternal TrustZone = "external"
	ZoneInternal TrustZone = "internal"
	ZoneBridge   TrustZone = "bridge"
)

type ServiceNode struct {
	Name         string    `json:"name"`
	Zone         TrustZone `json:"zone"`
	ExposedPorts []int     `json:"exposed_ports,omitempty"`
	DependsOn    []string  `json:"depends_on,omitempty"`
}

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type Report struct {
	Path     string        `json:"path"`
	Nodes    []ServiceNode `json:"nodes"`
	Findings []Finding     `json:"findings"`
	Summary  struct {
		TotalServices   int `json:"total_services"`
		ExternalCount   int `json:"external_count"`
		InternalCount   int `json:"internal_count"`
		BridgeCount     int `json:"bridge_count"`
		FindingCount    int `json:"finding_count"`
	} `json:"summary"`
}

func hasExternalPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func externalPorts(svc compose.Service) []int {
	var ports []int
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			ports = append(ports, p.TargetPort)
		}
	}
	return ports
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}

	allServices := map[string]compose.Service{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			allServices[svc.Name] = svc
		}
	}

	if len(allServices) == 0 {
		return r
	}

	externalSvcs := map[string]bool{}
	for name, svc := range allServices {
		if hasExternalPort(svc) {
			externalSvcs[name] = true
		}
	}

	dependsOnTargets := map[string]bool{}
	for _, svc := range allServices {
		for dep := range svc.DependsOn {
			dependsOnTargets[dep] = true
		}
	}

	names := make([]string, 0, len(allServices))
	for n := range allServices {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		svc := allServices[name]
		isExternal := externalSvcs[name]
		hasInternalConnections := len(svc.DependsOn) > 0 || dependsOnTargets[name]

		var zone TrustZone
		if isExternal && hasInternalConnections {
			zone = ZoneBridge
		} else if isExternal {
			zone = ZoneExternal
		} else {
			zone = ZoneInternal
		}

		var deps []string
		for d := range svc.DependsOn {
			deps = append(deps, d)
		}
		sort.Strings(deps)

		node := ServiceNode{
			Name:         name,
			Zone:         zone,
			ExposedPorts: externalPorts(svc),
			DependsOn:    deps,
		}
		r.Nodes = append(r.Nodes, node)

		switch zone {
		case ZoneExternal:
			r.Summary.ExternalCount++
		case ZoneInternal:
			r.Summary.InternalCount++
		case ZoneBridge:
			r.Summary.BridgeCount++
		}
	}
	r.Summary.TotalServices = len(r.Nodes)

	for _, name := range names {
		svc := allServices[name]
		if externalSvcs[name] && len(svc.DependsOn) > 0 {
			for dep := range svc.DependsOn {
				if !externalSvcs[dep] {
					r.Findings = append(r.Findings, Finding{
						Level:   "high",
						Rule:    "trust_bridge",
						Message: fmt.Sprintf("service %q bridges external traffic to internal service %q", name, dep),
					})
				}
			}
		}
	}

	for _, name := range names {
		svc := allServices[name]
		if svc.NetworkMode == "host" && externalSvcs[name] {
			r.Findings = append(r.Findings, Finding{
				Level:   "critical",
				Rule:    "trust_host_network_exposed",
				Message: fmt.Sprintf("service %q uses host networking with exposed ports — bypasses container network isolation", name),
			})
		}
	}

	for _, name := range names {
		svc := allServices[name]
		for dep := range svc.DependsOn {
			if _, ok := allServices[dep]; !ok {
				r.Findings = append(r.Findings, Finding{
					Level:   "medium",
					Rule:    "trust_missing_dependency",
					Message: fmt.Sprintf("service %q depends on %q which is not defined in compose files", name, dep),
				})
			}
		}
	}

	r.Summary.FindingCount = len(r.Findings)
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Trust Chain Analysis\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Nodes) == 0 {
		b.WriteString("  No services found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  Services: %d (external=%d internal=%d bridge=%d)\n\n",
		r.Summary.TotalServices, r.Summary.ExternalCount, r.Summary.InternalCount, r.Summary.BridgeCount)

	b.WriteString("  Trust Topology:\n")
	for _, n := range r.Nodes {
		ports := ""
		if len(n.ExposedPorts) > 0 {
			ps := make([]string, len(n.ExposedPorts))
			for i, p := range n.ExposedPorts {
				ps[i] = fmt.Sprintf("%d", p)
			}
			ports = fmt.Sprintf(" ports=[%s]", strings.Join(ps, ","))
		}
		deps := ""
		if len(n.DependsOn) > 0 {
			deps = fmt.Sprintf(" -> %s", strings.Join(n.DependsOn, ", "))
		}
		fmt.Fprintf(&b, "    [%s] %s%s%s\n", n.Zone, n.Name, ports, deps)
	}

	if len(r.Findings) > 0 {
		b.WriteString("\n  Findings:\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
	}

	return b.String()
}
