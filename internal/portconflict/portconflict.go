package portconflict

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type PortBinding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	HostPort int    `json:"host_port"`
	HostIP   string `json:"host_ip,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type Conflict struct {
	HostPort int           `json:"host_port"`
	HostIP   string        `json:"host_ip"`
	Severity string        `json:"severity"`
	Services []PortBinding `json:"services"`
}

type Summary struct {
	TotalPorts     int `json:"total_ports"`
	UniqueHostPorts int `json:"unique_host_ports"`
	Conflicts      int `json:"conflicts"`
	CriticalCount  int `json:"critical_count"`
	HighCount      int `json:"high_count"`
}

type Report struct {
	Summary   Summary    `json:"summary"`
	Conflicts []Conflict `json:"conflicts"`
	AllPorts  []PortBinding `json:"all_ports"`
}

func Analyze(c *collect.Collected) Report {
	var bindings []PortBinding

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, p := range svc.Ports {
				if p.HostPort == 0 {
					continue
				}
				ip := p.HostIP
				if ip == "" {
					ip = "0.0.0.0"
				}
				bindings = append(bindings, PortBinding{
					Service:  svc.Name,
					File:     cf.Path,
					HostPort: p.HostPort,
					HostIP:   ip,
					Line:     svc.PortsLine,
				})
			}
		}
	}

	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].HostPort != bindings[j].HostPort {
			return bindings[i].HostPort < bindings[j].HostPort
		}
		return bindings[i].Service < bindings[j].Service
	})

	type key struct {
		port int
		ip   string
	}
	groups := make(map[key][]PortBinding)
	for _, b := range bindings {
		k := key{b.HostPort, b.HostIP}
		groups[k] = append(groups[k], b)
		if b.HostIP != "0.0.0.0" {
			wk := key{b.HostPort, "0.0.0.0"}
			if _, ok := groups[wk]; ok {
				// handled below
			}
		}
	}

	var conflicts []Conflict
	seen := make(map[key]bool)
	for k, bs := range groups {
		if seen[k] || len(bs) < 2 {
			continue
		}
		seen[k] = true

		sameIP := allSameIP(bs)
		sev := "high"
		if sameIP {
			sev = "critical"
		}

		conflicts = append(conflicts, Conflict{
			HostPort: k.port,
			HostIP:   k.ip,
			Severity: sev,
			Services: bs,
		})
	}

	// Also check cross-IP conflicts: 0.0.0.0:X and 127.0.0.1:X overlap
	for k1, bs1 := range groups {
		for k2, bs2 := range groups {
			if k1.port != k2.port || k1.ip == k2.ip {
				continue
			}
			ck := key{k1.port, "mixed"}
			if seen[ck] {
				continue
			}
			if k1.ip == "0.0.0.0" || k2.ip == "0.0.0.0" {
				seen[ck] = true
				merged := append(append([]PortBinding{}, bs1...), bs2...)
				if len(uniqueServices(merged)) > 1 {
					conflicts = append(conflicts, Conflict{
						HostPort: k1.port,
						HostIP:   "mixed",
						Severity: "high",
						Services: merged,
					})
				}
			}
		}
	}

	sort.Slice(conflicts, func(i, j int) bool {
		if sevRank(conflicts[i].Severity) != sevRank(conflicts[j].Severity) {
			return sevRank(conflicts[i].Severity) > sevRank(conflicts[j].Severity)
		}
		return conflicts[i].HostPort < conflicts[j].HostPort
	})

	uniquePorts := make(map[int]bool)
	for _, b := range bindings {
		uniquePorts[b.HostPort] = true
	}

	r := Report{
		Summary: Summary{
			TotalPorts:      len(bindings),
			UniqueHostPorts: len(uniquePorts),
			Conflicts:       len(conflicts),
		},
		Conflicts: conflicts,
		AllPorts:  bindings,
	}
	for _, c := range conflicts {
		switch c.Severity {
		case "critical":
			r.Summary.CriticalCount++
		case "high":
			r.Summary.HighCount++
		}
	}
	return r
}

func allSameIP(bs []PortBinding) bool {
	if len(bs) == 0 {
		return true
	}
	ip := bs[0].HostIP
	for _, b := range bs[1:] {
		if b.HostIP != ip {
			return false
		}
	}
	return true
}

func uniqueServices(bs []PortBinding) []string {
	m := make(map[string]bool)
	for _, b := range bs {
		m[b.Service] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Port Conflict Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	if r.Summary.TotalPorts == 0 {
		b.WriteString("  No port bindings found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  Total port bindings:  %d\n", r.Summary.TotalPorts)
	fmt.Fprintf(&b, "  Unique host ports:    %d\n", r.Summary.UniqueHostPorts)
	fmt.Fprintf(&b, "  Conflicts:            %d\n", r.Summary.Conflicts)
	b.WriteString("\n")

	if len(r.Conflicts) > 0 {
		b.WriteString("Conflicts\n")
		b.WriteString(strings.Repeat("-", 62) + "\n")
		for _, c := range r.Conflicts {
			svcs := make([]string, 0, len(c.Services))
			for _, s := range c.Services {
				svcs = append(svcs, s.Service)
			}
			fmt.Fprintf(&b, "  [%s] port %d (%s): %s\n",
				strings.ToUpper(c.Severity), c.HostPort, c.HostIP,
				strings.Join(svcs, ", "))
		}
		b.WriteString("\n")
	}

	if len(r.AllPorts) > 0 {
		b.WriteString("All Port Bindings\n")
		b.WriteString(strings.Repeat("-", 62) + "\n")
		for _, p := range r.AllPorts {
			fmt.Fprintf(&b, "  %s:%d -> %s\n", p.HostIP, p.HostPort, p.Service)
		}
		b.WriteString("\n")
	}

	return b.String()
}
