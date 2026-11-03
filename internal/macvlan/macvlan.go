package macvlan

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
	TotalServices       int `json:"total_services"`
	TotalNetworks       int `json:"total_networks"`
	TotalFindings       int `json:"total_findings"`
	MacvlanDrivers      int `json:"macvlan_drivers"`
	PromiscuousMode     int `json:"promiscuous_mode"`
	MissingVlanTag      int `json:"missing_vlan_tag"`
	BroadcastExposure   int `json:"broadcast_exposure"`
	IpvlanDrivers       int `json:"ipvlan_drivers"`
	DirectHostAccess    int `json:"direct_host_access"`
}

var macvlanKeywords = []string{
	"macvlan", "ipvlan",
}

var promiscuousKeywords = []string{
	"promisc", "promiscuous", "iff_promisc",
}

func isMacvlanRelated(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range macvlanKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isMacvlanMode(mode string) bool {
	lower := strings.ToLower(mode)
	return strings.Contains(lower, "macvlan") || strings.Contains(lower, "ipvlan")
}

func isPromiscuous(envVars []string) bool {
	for _, e := range envVars {
		lower := strings.ToLower(e)
		for _, kw := range promiscuousKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return false
}

func hasVlanTag(envVars []string) bool {
	for _, e := range envVars {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "vlan_id") || strings.Contains(lower, "vlan_tag") || strings.Contains(lower, "parent_iface.") {
			return true
		}
	}
	return false
}

func hasParentInterface(envVars []string) bool {
	for _, e := range envVars {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "parent") || strings.Contains(lower, "master_iface") || strings.Contains(lower, "host_iface") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if isMacvlanMode(svc.NetworkMode) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "macvlan_network_mode",
			Message: fmt.Sprintf("Service '%s' uses macvlan/ipvlan network mode '%s'; containers get direct Layer 2 access to the physical network", svc.Name, svc.NetworkMode),
		})

		if hasParentInterface(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "direct_host_access",
				Message: fmt.Sprintf("Service '%s' binds to host parent interface via macvlan; the container appears as a physical device on the LAN", svc.Name),
			})
		}
	}

	if isPromiscuous(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "promiscuous_mode",
			Message: fmt.Sprintf("Service '%s' enables promiscuous mode; the container can sniff all traffic on its network segment", svc.Name),
		})
	}

	if isMacvlanMode(svc.NetworkMode) && !hasVlanTag(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_vlan_tag",
			Message: fmt.Sprintf("Service '%s' uses macvlan without explicit VLAN tagging; traffic may traverse the default broadcast domain", svc.Name),
		})
	}

	for _, cap := range svc.CapAdd {
		upper := strings.ToUpper(cap)
		if upper == "NET_RAW" || upper == "NET_ADMIN" {
			if isMacvlanMode(svc.NetworkMode) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "macvlan_dangerous_cap",
					Message: fmt.Sprintf("Service '%s' combines macvlan with %s capability; this grants ARP spoofing and traffic manipulation abilities", svc.Name, upper),
				})
			}
		}
	}

	for _, v := range svc.Volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "/sys/class/net") || strings.Contains(lower, "/proc/sys/net") {
			if isMacvlanMode(svc.NetworkMode) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "macvlan_sysfs_mount",
					Message: fmt.Sprintf("Service '%s' mounts network sysfs '%s' with macvlan; the container can reconfigure network interfaces", svc.Name, v),
				})
			}
		}
	}

	return sr
}

func analyzeNetwork(name string, net compose.Network, file string) NetworkResult {
	nr := NetworkResult{Network: name, File: file}

	lower := strings.ToLower(name)
	if strings.Contains(lower, "macvlan") {
		nr.Findings = append(nr.Findings, Finding{
			Level:   "low",
			Rule:    "macvlan_network_detected",
			Message: fmt.Sprintf("Macvlan network '%s' detected; containers share Layer 2 with the host network", name),
		})
		if !net.Internal {
			nr.Findings = append(nr.Findings, Finding{
				Level:   "medium",
				Rule:    "macvlan_broadcast_exposure",
				Message: fmt.Sprintf("Macvlan network '%s' is not internal; containers participate in the physical broadcast domain", name),
			})
		}
	}

	if strings.Contains(lower, "ipvlan") {
		nr.Findings = append(nr.Findings, Finding{
			Level:   "low",
			Rule:    "ipvlan_network_detected",
			Message: fmt.Sprintf("Ipvlan network '%s' detected; containers share the host MAC address and are visible on the physical network", name),
		})
		if !net.Internal {
			nr.Findings = append(nr.Findings, Finding{
				Level:   "medium",
				Rule:    "ipvlan_broadcast_exposure",
				Message: fmt.Sprintf("Ipvlan network '%s' is not internal; containers are exposed on the physical broadcast domain", name),
			})
		}
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
			case "promiscuous_mode":
				s.PromiscuousMode++
			case "missing_vlan_tag":
				s.MissingVlanTag++
			case "direct_host_access":
				s.DirectHostAccess++
			}
		}
	}
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "macvlan_network_detected":
				s.MacvlanDrivers++
			case "ipvlan_network_detected":
				s.IpvlanDrivers++
			case "macvlan_broadcast_exposure", "ipvlan_broadcast_exposure":
				s.BroadcastExposure++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Macvlan/Ipvlan Network Audit (%d services, %d networks, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalNetworks, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Macvlan networks:          %d\n", r.Summary.MacvlanDrivers)
	fmt.Fprintf(&b, "  Ipvlan networks:           %d\n", r.Summary.IpvlanDrivers)
	fmt.Fprintf(&b, "  Promiscuous mode:          %d\n", r.Summary.PromiscuousMode)
	fmt.Fprintf(&b, "  Missing VLAN tags:         %d\n", r.Summary.MissingVlanTag)
	fmt.Fprintf(&b, "  Broadcast exposure:        %d\n", r.Summary.BroadcastExposure)
	fmt.Fprintf(&b, "  Direct host access:        %d\n\n", r.Summary.DirectHostAccess)
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
