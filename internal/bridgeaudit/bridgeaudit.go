package bridgeaudit

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
	TotalServices            int `json:"total_services"`
	TotalFindings            int `json:"total_findings"`
	DefaultBridgeNetworks    int `json:"default_bridge_networks"`
	MissingICCIsolation      int `json:"missing_icc_isolation"`
	NoNetworkSegmentation    int `json:"no_network_segmentation"`
	UnrestrictedContainerComm int `json:"unrestricted_container_comm"`
	PrivilegedOnBridge       int `json:"privileged_on_bridge"`
}

func isDefaultBridge(svc compose.Service) bool {
	mode := strings.TrimSpace(strings.ToLower(svc.NetworkMode))
	return mode == "" || mode == "bridge" || mode == "default"
}

func analyzeService(svc compose.Service, file string, bridgePeerCount int, fileNetworks map[string]compose.Network) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if isDefaultBridge(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "default_bridge_network",
			Message: fmt.Sprintf("Service '%s' uses the default bridge network; consider using a user-defined network for better isolation and DNS resolution", svc.Name),
		})

		if bridgePeerCount > 1 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "missing_icc_isolation",
				Message: fmt.Sprintf("Service '%s' shares the default bridge with %d other service(s); inter-container communication (ICC) is unrestricted on the default bridge", svc.Name, bridgePeerCount-1),
			})
		}

		if svc.Privileged {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "privileged_on_bridge",
				Message: fmt.Sprintf("Service '%s' runs privileged on the default bridge network; a compromised privileged container can sniff and manipulate all bridge traffic", svc.Name),
			})
		}

		for _, c := range svc.CapAdd {
			upper := strings.ToUpper(c)
			if upper == "NET_ADMIN" || upper == "NET_RAW" || upper == "ALL" {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "unrestricted_container_comm",
					Message: fmt.Sprintf("Service '%s' has %s capability on the default bridge; this allows network packet manipulation and traffic interception", svc.Name, upper),
				})
				break
			}
		}
	}

	mode := strings.TrimSpace(strings.ToLower(svc.NetworkMode))
	if mode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "unrestricted_container_comm",
			Message: fmt.Sprintf("Service '%s' uses host network mode; it bypasses all Docker network isolation", svc.Name),
		})
	}

	hasInternalNet := false
	for _, net := range fileNetworks {
		if net.Internal {
			hasInternalNet = true
			break
		}
	}
	if isDefaultBridge(svc) && !hasInternalNet && len(fileNetworks) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_network_segmentation",
			Message: fmt.Sprintf("Service '%s' has no user-defined networks; all services communicate over the default bridge without segmentation", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		bridgeCount := 0
		for _, svc := range cf.Services {
			if isDefaultBridge(svc) {
				bridgeCount++
			}
		}
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, bridgeCount, cf.Networks)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "default_bridge_network":
				s.DefaultBridgeNetworks++
			case "missing_icc_isolation":
				s.MissingICCIsolation++
			case "no_network_segmentation":
				s.NoNetworkSegmentation++
			case "unrestricted_container_comm":
				s.UnrestrictedContainerComm++
			case "privileged_on_bridge":
				s.PrivilegedOnBridge++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bridge Network Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Default bridge networks:      %d\n", r.Summary.DefaultBridgeNetworks)
	fmt.Fprintf(&b, "  Missing ICC isolation:         %d\n", r.Summary.MissingICCIsolation)
	fmt.Fprintf(&b, "  No network segmentation:       %d\n", r.Summary.NoNetworkSegmentation)
	fmt.Fprintf(&b, "  Unrestricted container comm:   %d\n", r.Summary.UnrestrictedContainerComm)
	fmt.Fprintf(&b, "  Privileged on bridge:          %d\n\n", r.Summary.PrivilegedOnBridge)
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
