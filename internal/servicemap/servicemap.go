package servicemap

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type ServiceNode struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	Image      string   `json:"image,omitempty"`
	Ports      []string `json:"ports,omitempty"`
	Networks   []string `json:"networks,omitempty"`
	DependsOn  []string `json:"depends_on,omitempty"`
	VolumeSrcs []string `json:"volume_sources,omitempty"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

type ServiceMap struct {
	Nodes []ServiceNode `json:"nodes"`
	Edges []Edge        `json:"edges"`
	Stats MapStats      `json:"stats"`
}

type MapStats struct {
	TotalServices int `json:"total_services"`
	TotalEdges    int `json:"total_edges"`
	Isolated      int `json:"isolated_services"`
	MaxFanOut     int `json:"max_fan_out"`
}

func Analyze(collected *collect.Collected) ServiceMap {
	var nodes []ServiceNode
	var edges []Edge
	edgeSet := map[string]bool{}

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			svc := &cf.Services[i]
			node := buildNode(svc, cf.Path)
			nodes = append(nodes, node)

			for dep := range svc.DependsOn {
				key := svc.Name + "->" + dep
				if !edgeSet[key] {
					edgeSet[key] = true
					edges = append(edges, Edge{From: svc.Name, To: dep, Type: "depends_on"})
				}
			}
		}

		networkMembers := map[string][]string{}
		for i := range cf.Services {
			for _, net := range serviceNetworks(&cf.Services[i]) {
				networkMembers[net] = append(networkMembers[net], cf.Services[i].Name)
			}
		}
		for _, members := range networkMembers {
			for i := 0; i < len(members); i++ {
				for j := i + 1; j < len(members); j++ {
					key := members[i] + "<->" + members[j]
					if !edgeSet[key] {
						edgeSet[key] = true
						edges = append(edges, Edge{From: members[i], To: members[j], Type: "shared_network"})
					}
				}
			}
		}
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		return edges[i].To < edges[j].To
	})

	connected := map[string]bool{}
	fanOut := map[string]int{}
	for _, e := range edges {
		connected[e.From] = true
		connected[e.To] = true
		fanOut[e.From]++
	}

	stats := MapStats{
		TotalServices: len(nodes),
		TotalEdges:    len(edges),
	}
	for _, n := range nodes {
		if !connected[n.Name] {
			stats.Isolated++
		}
	}
	for _, count := range fanOut {
		if count > stats.MaxFanOut {
			stats.MaxFanOut = count
		}
	}

	return ServiceMap{Nodes: nodes, Edges: edges, Stats: stats}
}

func buildNode(svc *compose.Service, file string) ServiceNode {
	node := ServiceNode{
		Name:  svc.Name,
		File:  file,
		Image: svc.Image,
	}

	for _, p := range svc.Ports {
		if p.HostIP != "" {
			node.Ports = append(node.Ports, fmt.Sprintf("%s:%d->%d", p.HostIP, p.HostPort, p.TargetPort))
		} else {
			node.Ports = append(node.Ports, fmt.Sprintf("%d->%d", p.HostPort, p.TargetPort))
		}
	}

	node.Networks = serviceNetworks(svc)

	for dep := range svc.DependsOn {
		node.DependsOn = append(node.DependsOn, dep)
	}
	sort.Strings(node.DependsOn)

	for _, v := range svc.Volumes {
		parts := strings.SplitN(v, ":", 2)
		if len(parts) > 0 {
			node.VolumeSrcs = append(node.VolumeSrcs, parts[0])
		}
	}

	return node
}

func serviceNetworks(svc *compose.Service) []string {
	if svc.NetworkMode != "" && svc.NetworkMode != "bridge" {
		return []string{svc.NetworkMode}
	}
	return []string{"default"}
}

func FormatText(sm ServiceMap) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Service Map (%d services, %d edges, %d isolated)\n\n",
		sm.Stats.TotalServices, sm.Stats.TotalEdges, sm.Stats.Isolated)

	for _, n := range sm.Nodes {
		fmt.Fprintf(&b, "  %s", n.Name)
		if n.Image != "" {
			fmt.Fprintf(&b, " (%s)", n.Image)
		}
		fmt.Fprintf(&b, " [%s]\n", n.File)
		if len(n.Ports) > 0 {
			fmt.Fprintf(&b, "    ports: %s\n", strings.Join(n.Ports, ", "))
		}
		if len(n.DependsOn) > 0 {
			fmt.Fprintf(&b, "    depends_on: %s\n", strings.Join(n.DependsOn, ", "))
		}
	}

	if len(sm.Edges) > 0 {
		b.WriteString("\n  Edges:\n")
		for _, e := range sm.Edges {
			fmt.Fprintf(&b, "    %s -> %s [%s]\n", e.From, e.To, e.Type)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func FormatDOT(sm ServiceMap) string {
	var b strings.Builder
	b.WriteString("digraph service_map {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box, style=rounded];\n\n")

	for _, n := range sm.Nodes {
		label := n.Name
		if n.Image != "" {
			label += "\\n" + n.Image
		}
		fmt.Fprintf(&b, "  %q [label=%q];\n", n.Name, label)
	}
	b.WriteString("\n")

	for _, e := range sm.Edges {
		style := "solid"
		if e.Type == "shared_network" {
			style = "dashed"
		}
		fmt.Fprintf(&b, "  %q -> %q [label=%q, style=%s];\n", e.From, e.To, e.Type, style)
	}

	b.WriteString("}\n")
	return b.String()
}
