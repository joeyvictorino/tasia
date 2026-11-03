package extnet

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

type NetworkResult struct {
	Network  string    `json:"network"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Networks []NetworkResult `json:"networks"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalNetworks     int `json:"total_networks"`
	TotalFindings     int `json:"total_findings"`
	NonInternal       int `json:"non_internal"`
	NoNetworksDefined int `json:"no_networks_defined"`
	ServiceCount      int `json:"service_count"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	totalSvcs := 0
	for _, cf := range c.ComposeFiles {
		totalSvcs += len(cf.Services)
		if len(cf.Networks) == 0 && len(cf.Services) > 1 {
			r.Networks = append(r.Networks, NetworkResult{
				Network: "(default)",
				File:    cf.Path,
				Findings: []Finding{{
					Level:   "medium",
					Rule:    "no_networks_defined",
					Message: fmt.Sprintf("Compose file '%s' defines %d services without explicit networks; all services share a flat default network", cf.Path, len(cf.Services)),
				}},
			})
		}
		for name, net := range cf.Networks {
			nr := analyzeNetwork(name, net, cf)
			r.Networks = append(r.Networks, nr)
		}
	}
	r.Summary = summarize(r.Networks)
	r.Summary.ServiceCount = totalSvcs
	return r
}

func analyzeNetwork(name string, net compose.Network, cf compose.File) NetworkResult {
	nr := NetworkResult{Network: name, File: cf.Path}

	if !net.Internal {
		nr.Findings = append(nr.Findings, Finding{
			Level:   "medium",
			Rule:    "network_not_internal",
			Message: fmt.Sprintf("Network '%s' is not marked internal; containers on it can reach external hosts and be reached from outside", name),
		})

		svcCount := countServicesOnNetwork(name, cf)
		if svcCount > 3 {
			nr.Findings = append(nr.Findings, Finding{
				Level:   "medium",
				Rule:    "broad_external_network",
				Message: fmt.Sprintf("Network '%s' is non-internal and shared by %d services; consider splitting into smaller segments", name, svcCount),
			})
		}

		hasPrivileged := false
		for _, svc := range cf.Services {
			if svc.Privileged && isOnNetwork(svc, name, cf) {
				hasPrivileged = true
			}
		}
		if hasPrivileged {
			nr.Findings = append(nr.Findings, Finding{
				Level:   "high",
				Rule:    "privileged_on_external",
				Message: fmt.Sprintf("Network '%s' is non-internal and has privileged containers; network-reachable attackers can target privileged services", name),
			})
		}
	}

	return nr
}

func countServicesOnNetwork(name string, cf compose.File) int {
	count := 0
	for _, svc := range cf.Services {
		if isOnNetwork(svc, name, cf) {
			count++
		}
	}
	return count
}

func isOnNetwork(svc compose.Service, name string, cf compose.File) bool {
	if svc.NetworkMode != "" {
		return false
	}
	if len(cf.Networks) == 0 {
		return true
	}
	return true
}

func summarize(networks []NetworkResult) Summary {
	s := Summary{TotalNetworks: len(networks)}
	for _, nr := range networks {
		for _, f := range nr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "network_not_internal":
				s.NonInternal++
			case "no_networks_defined":
				s.NoNetworksDefined++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "External Network Security Audit (%d networks, %d findings)\n\n", r.Summary.TotalNetworks, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Non-internal networks: %d\n", r.Summary.NonInternal)
	fmt.Fprintf(&b, "  No networks defined:   %d\n", r.Summary.NoNetworksDefined)
	fmt.Fprintf(&b, "  Total services:        %d\n\n", r.Summary.ServiceCount)
	for _, nr := range r.Networks {
		fmt.Fprintf(&b, "  %-30s\n", nr.Network)
		fmt.Fprintf(&b, "    file: %s\n", nr.File)
		if len(nr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range nr.Findings {
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
