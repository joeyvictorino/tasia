package netanalyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type NetworkInfo struct {
	Name     string   `json:"name"`
	Driver   string   `json:"driver"`
	Internal bool     `json:"internal"`
	Services []string `json:"services"`
}

type ServiceConnection struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Network string `json:"network"`
	Ports   []int  `json:"ports"`
}

type NetworkAnalysis struct {
	Networks    []NetworkInfo       `json:"networks"`
	Connections []ServiceConnection `json:"connections"`
	Findings    []NetworkFinding    `json:"findings"`
	Score       float64             `json:"score"`
}

type NetworkFinding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Network  string `json:"network"`
	Service  string `json:"service"`
}

func AnalyzeNetworks(collected *collect.Collected) NetworkAnalysis {
	result := NetworkAnalysis{Score: 100}

	netServices := map[string][]string{}
	netInternal := map[string]bool{}

	for _, cf := range collected.ComposeFiles {
		for netName, net := range cf.Networks {
			netInternal[netName] = net.Internal
			if _, ok := netServices[netName]; !ok {
				netServices[netName] = nil
			}
		}

		svcNetMap := buildServiceNetworkMap(cf)

		for _, svc := range cf.Services {
			if svc.NetworkMode == "host" {
				result.Findings = append(result.Findings, NetworkFinding{
					Severity: "high",
					Message:  fmt.Sprintf("Service %q uses network_mode: host, bypassing network isolation", svc.Name),
					Service:  svc.Name,
				})
				continue
			}

			nets := svcNetMap[svc.Name]
			if len(nets) == 0 && len(cf.Networks) > 0 {
				result.Findings = append(result.Findings, NetworkFinding{
					Severity: "low",
					Message:  fmt.Sprintf("Service %q is not assigned to any explicit network", svc.Name),
					Service:  svc.Name,
				})
				netServices["default"] = append(netServices["default"], svc.Name)
			} else if len(nets) == 0 {
				netServices["default"] = append(netServices["default"], svc.Name)
			}

			for _, n := range nets {
				netServices[n] = append(netServices[n], svc.Name)
			}

			if hasExposedPorts(svc) {
				for _, n := range nets {
					if !netInternal[n] {
						result.Findings = append(result.Findings, NetworkFinding{
							Severity: "medium",
							Message:  fmt.Sprintf("Service %q exposes ports on non-internal network %q", svc.Name, n),
							Network:  n,
							Service:  svc.Name,
						})
					}
				}
			}
		}
	}

	if svcs, ok := netServices["default"]; ok && len(svcs) > 1 {
		result.Findings = append(result.Findings, NetworkFinding{
			Severity: "medium",
			Message:  fmt.Sprintf("%d services share the default bridge network: %s", len(svcs), strings.Join(svcs, ", ")),
			Network:  "default",
		})
	}

	for netName, isInternal := range netInternal {
		if !isInternal && len(netServices[netName]) > 2 {
			result.Findings = append(result.Findings, NetworkFinding{
				Severity: "medium",
				Message:  fmt.Sprintf("Network %q has %d services but is not marked internal", netName, len(netServices[netName])),
				Network:  netName,
			})
		}
	}

	names := make([]string, 0, len(netServices))
	for n := range netServices {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svcs := netServices[n]
		sort.Strings(svcs)
		ni := NetworkInfo{
			Name:     n,
			Internal: netInternal[n],
			Services: svcs,
		}
		if n == "default" {
			ni.Driver = "bridge"
		}
		result.Networks = append(result.Networks, ni)
	}

	result.Connections = buildConnections(netServices)

	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			result.Score -= 20
		case "high":
			result.Score -= 15
		case "medium":
			result.Score -= 10
		case "low":
			result.Score -= 5
		}
	}
	if result.Score < 0 {
		result.Score = 0
	}

	return result
}

func buildServiceNetworkMap(cf compose.File) map[string][]string {
	result := map[string][]string{}
	for _, svc := range cf.Services {
		for _, env := range svc.Environment {
			_ = env
		}
	}
	for netName := range cf.Networks {
		for _, svc := range cf.Services {
			for _, env := range svc.Environment {
				if strings.Contains(env, netName) {
					result[svc.Name] = append(result[svc.Name], netName)
				}
			}
		}
	}
	return result
}

func hasExposedPorts(svc compose.Service) bool {
	return len(svc.Ports) > 0
}

func buildConnections(netServices map[string][]string) []ServiceConnection {
	var conns []ServiceConnection
	seen := map[string]bool{}
	for netName, svcs := range netServices {
		for i := 0; i < len(svcs); i++ {
			for j := i + 1; j < len(svcs); j++ {
				key := svcs[i] + ":" + svcs[j] + ":" + netName
				if seen[key] {
					continue
				}
				seen[key] = true
				conns = append(conns, ServiceConnection{
					From:    svcs[i],
					To:      svcs[j],
					Network: netName,
				})
			}
		}
	}
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Network != conns[j].Network {
			return conns[i].Network < conns[j].Network
		}
		if conns[i].From != conns[j].From {
			return conns[i].From < conns[j].From
		}
		return conns[i].To < conns[j].To
	})
	return conns
}

func FormatText(a NetworkAnalysis) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Network Security Analysis (Score: %.0f/100)\n\n", a.Score)

	if len(a.Networks) > 0 {
		fmt.Fprintln(&b, "Networks:")
		for _, n := range a.Networks {
			internal := ""
			if n.Internal {
				internal = " [internal]"
			}
			fmt.Fprintf(&b, "  %-20s %d services%s\n", n.Name, len(n.Services), internal)
		}
		fmt.Fprintln(&b)
	}

	if len(a.Connections) > 0 {
		fmt.Fprintln(&b, "Connections:")
		for _, c := range a.Connections {
			fmt.Fprintf(&b, "  %s <-> %s  (via %s)\n", c.From, c.To, c.Network)
		}
		fmt.Fprintln(&b)
	}

	if len(a.Findings) > 0 {
		fmt.Fprintf(&b, "Findings (%d):\n", len(a.Findings))
		for _, f := range a.Findings {
			fmt.Fprintf(&b, "  [%s] %s\n", strings.ToUpper(f.Severity), f.Message)
		}
	} else {
		fmt.Fprintln(&b, "No network security findings.")
	}

	return b.String()
}

func FormatDOT(a NetworkAnalysis) string {
	var b strings.Builder
	fmt.Fprintln(&b, "digraph network {")
	fmt.Fprintln(&b, "  rankdir=LR;")
	fmt.Fprintln(&b, "  node [shape=box];")

	for i, n := range a.Networks {
		fmt.Fprintf(&b, "  subgraph cluster_%d {\n", i)
		fmt.Fprintf(&b, "    label=%q;\n", n.Name)
		if n.Internal {
			fmt.Fprintln(&b, "    style=dashed;")
		}
		for _, svc := range n.Services {
			fmt.Fprintf(&b, "    %q;\n", svc)
		}
		fmt.Fprintln(&b, "  }")
	}

	for _, c := range a.Connections {
		fmt.Fprintf(&b, "  %q -> %q [label=%q, dir=both];\n", c.From, c.To, c.Network)
	}

	fmt.Fprintln(&b, "}")
	return b.String()
}
