package vxlan

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

type NetworkResult struct {
	Network  string    `json:"network"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Networks []NetworkResult `json:"networks"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices      int `json:"total_services"`
	TotalNetworks      int `json:"total_networks"`
	TotalFindings      int `json:"total_findings"`
	VxlanDrivers       int `json:"vxlan_drivers"`
	MissingEncryption  int `json:"missing_encryption"`
	MissingVNI         int `json:"missing_vni"`
	BroadSubnets       int `json:"broad_subnets"`
	OverlayNoIsolation int `json:"overlay_no_isolation"`
}

var vxlanDriverKeywords = []string{
	"overlay", "vxlan",
}

var broadSubnets = []string{
	"/8", "/12", "/16", "0.0.0.0",
}

func isVxlanRelated(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range vxlanDriverKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isBroadSubnet(subnet string) bool {
	for _, bs := range broadSubnets {
		if strings.Contains(subnet, bs) {
			return true
		}
	}
	return false
}

func hasEncryptionEnv(envVars []string) bool {
	for _, e := range envVars {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "encrypt") && (strings.Contains(lower, "=true") || strings.Contains(lower, "=yes") || strings.Contains(lower, "=1") || strings.Contains(lower, "ipsec")) {
			return true
		}
	}
	return false
}

func hasVNIConfig(envVars []string) bool {
	for _, e := range envVars {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "vni") || strings.Contains(lower, "vxlan_id") || strings.Contains(lower, "vxlan_vni") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if isVxlanRelated(svc.NetworkMode) {
		if !hasEncryptionEnv(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "vxlan_no_encryption",
				Message: fmt.Sprintf("Service '%s' uses overlay/VXLAN network mode '%s' without encryption; VXLAN traffic is sent in cleartext by default", svc.Name, svc.NetworkMode),
			})
		}
		if !hasVNIConfig(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "vxlan_missing_vni",
				Message: fmt.Sprintf("Service '%s' uses overlay network mode '%s' without explicit VNI configuration; services may share the default VNI reducing isolation", svc.Name, svc.NetworkMode),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.ToLower(parts[1])

		if strings.Contains(key, "vxlan") || strings.Contains(key, "overlay") || strings.Contains(key, "vtep") {
			if strings.Contains(key, "port") && (val == "4789" || val == "8472") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "vxlan_default_port",
					Message: fmt.Sprintf("Service '%s' uses default VXLAN port %s; consider a non-standard port to reduce attack surface", svc.Name, parts[1]),
				})
			}
		}

		if strings.Contains(key, "subnet") && isBroadSubnet(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "vxlan_broad_subnet",
				Message: fmt.Sprintf("Service '%s' configures a broad overlay subnet '%s'; use narrower subnets to limit blast radius", svc.Name, parts[1]),
			})
		}
	}

	for _, v := range svc.Volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "vxlan") || strings.Contains(lower, "vtep") || strings.Contains(lower, "flannel") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "vxlan_config_mount",
				Message: fmt.Sprintf("Service '%s' mounts VXLAN/overlay configuration path '%s'; this exposes network tunnel configuration", svc.Name, v),
			})
		}
	}

	return sr
}

func analyzeNetwork(name string, net compose.Network, file string) NetworkResult {
	nr := NetworkResult{Network: name, File: file}

	if isVxlanRelated(name) {
		if !net.Internal {
			nr.Findings = append(nr.Findings, Finding{
				Level:   "medium",
				Rule:    "overlay_not_internal",
				Message: fmt.Sprintf("Overlay network '%s' is not marked internal; containers can route to external networks through this overlay", name),
			})
		}

		nr.Findings = append(nr.Findings, Finding{
			Level:   "low",
			Rule:    "overlay_network_detected",
			Message: fmt.Sprintf("Overlay/VXLAN network '%s' detected; ensure encryption is enabled and VNI isolation is configured", name),
		})
	}

	return nr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
		for name, net := range cf.Networks {
			nr := analyzeNetwork(name, net, cf.Path)
			r.Networks = append(r.Networks, nr)
		}
	}
	r.Summary = summarize(r)
	return r
}

func summarize(r Report) Summary {
	s := Summary{
		TotalServices: len(r.Services),
		TotalNetworks: len(r.Networks),
	}
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "vxlan_no_encryption":
				s.MissingEncryption++
			case "vxlan_missing_vni":
				s.MissingVNI++
			case "vxlan_broad_subnet":
				s.BroadSubnets++
			}
		}
	}
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "overlay_network_detected":
				s.VxlanDrivers++
			case "overlay_not_internal":
				s.OverlayNoIsolation++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "VXLAN Overlay Network Audit (%d services, %d networks, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalNetworks, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  VXLAN/overlay networks:     %d\n", r.Summary.VxlanDrivers)
	fmt.Fprintf(&b, "  Missing encryption:        %d\n", r.Summary.MissingEncryption)
	fmt.Fprintf(&b, "  Missing VNI isolation:     %d\n", r.Summary.MissingVNI)
	fmt.Fprintf(&b, "  Broad subnets:             %d\n", r.Summary.BroadSubnets)
	fmt.Fprintf(&b, "  Overlay no isolation:      %d\n\n", r.Summary.OverlayNoIsolation)
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
	for _, nr := range r.Networks {
		fmt.Fprintf(&b, "  network: %-30s\n", nr.Network)
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
