package portmap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type PortEntry struct {
	HostPort   int    `json:"host_port"`
	TargetPort int    `json:"target_port"`
	HostIP     string `json:"host_ip"`
	Service    string `json:"service"`
	File       string `json:"file"`
}

type PortMapResult struct {
	Path    string      `json:"path"`
	Entries []PortEntry `json:"entries"`
	Clashes []PortClash `json:"clashes,omitempty"`
}

type PortClash struct {
	HostPort int         `json:"host_port"`
	HostIP   string      `json:"host_ip"`
	Owners   []PortEntry `json:"owners"`
}

func Analyze(collected *collect.Collected) PortMapResult {
	var entries []PortEntry

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			for _, p := range svc.Ports {
				if p.HostPort == 0 {
					continue
				}
				ip := p.HostIP
				if ip == "" {
					ip = "0.0.0.0"
				}
				entries = append(entries, PortEntry{
					HostPort:   p.HostPort,
					TargetPort: p.TargetPort,
					HostIP:     ip,
					Service:    svc.Name,
					File:       cf.Path,
				})
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].HostPort != entries[j].HostPort {
			return entries[i].HostPort < entries[j].HostPort
		}
		return entries[i].Service < entries[j].Service
	})

	type clashKey struct {
		port int
		ip   string
	}
	groups := map[clashKey][]PortEntry{}
	for _, e := range entries {
		k := clashKey{port: e.HostPort, ip: e.HostIP}
		groups[k] = append(groups[k], e)
	}

	var clashes []PortClash
	for k, owners := range groups {
		if len(owners) > 1 {
			clashes = append(clashes, PortClash{
				HostPort: k.port,
				HostIP:   k.ip,
				Owners:   owners,
			})
		}
	}
	sort.Slice(clashes, func(i, j int) bool {
		return clashes[i].HostPort < clashes[j].HostPort
	})

	return PortMapResult{
		Path:    collected.Root,
		Entries: entries,
		Clashes: clashes,
	}
}

func FormatText(r PortMapResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Port Map: %s — %d allocation(s)\n\n", r.Path, len(r.Entries))

	if len(r.Entries) == 0 {
		b.WriteString("  No host port allocations found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  %-8s %-15s %-10s %-20s %s\n", "HOST", "INTERFACE", "TARGET", "SERVICE", "FILE")
	fmt.Fprintf(&b, "  %-8s %-15s %-10s %-20s %s\n", "----", "---------", "------", "-------", "----")
	for _, e := range r.Entries {
		fmt.Fprintf(&b, "  %-8d %-15s %-10d %-20s %s\n", e.HostPort, e.HostIP, e.TargetPort, e.Service, e.File)
	}

	if len(r.Clashes) > 0 {
		fmt.Fprintf(&b, "\nClashes (%d):\n", len(r.Clashes))
		for _, c := range r.Clashes {
			var owners []string
			for _, o := range c.Owners {
				owners = append(owners, fmt.Sprintf("%s(%s)", o.Service, o.File))
			}
			fmt.Fprintf(&b, "  port %d (%s): %s\n", c.HostPort, c.HostIP, strings.Join(owners, ", "))
		}
	}

	return b.String()
}

func FormatJSON(r PortMapResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
