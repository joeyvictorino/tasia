package ipblock

import (
	"fmt"
	"net"
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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	WideOpenNetworks  int `json:"wide_open_networks"`
	PrivateRangeExposed int `json:"private_range_exposed"`
	MissingIPRestrict int `json:"missing_ip_restrict"`
	BroadCIDRBlocks   int `json:"broad_cidr_blocks"`
	LoopbackExposed   int `json:"loopback_exposed"`
}

var broadCIDRThreshold = 16

var privateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

var sensitiveServices = []string{
	"postgres", "mysql", "mariadb", "mongo", "redis", "memcached",
	"elasticsearch", "kibana", "grafana", "prometheus",
	"rabbitmq", "kafka", "zookeeper", "etcd", "consul", "vault",
}

func isSensitiveService(name, image string) bool {
	lower := strings.ToLower(name + " " + image)
	for _, s := range sensitiveServices {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func isPrivateRange(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, pr := range privateRanges {
		_, privNet, err := net.ParseCIDR(pr)
		if err != nil {
			continue
		}
		if privNet.Contains(ipNet.IP) {
			return true
		}
	}
	return false
}

func isBroadCIDR(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := ipNet.Mask.Size()
	return ones <= broadCIDRThreshold
}

func isLoopback(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
	}
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func hasIPRestriction(envVars []string) bool {
	for _, e := range envVars {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "ALLOWED_IPS") ||
			strings.Contains(upper, "WHITELIST") ||
			strings.Contains(upper, "ALLOWLIST") ||
			strings.Contains(upper, "IP_RESTRICT") ||
			strings.Contains(upper, "TRUSTED_IPS") ||
			strings.Contains(upper, "ACCESS_CONTROL") ||
			strings.Contains(upper, "BIND_ADDRESS") {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, cf compose.File) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: cf.Path}

	sensitive := isSensitiveService(svc.Name, svc.Image)

	for _, port := range svc.Ports {
		raw := port.Raw
		if port.IsAllInterfaces() {
			if sensitive {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "ipblock_wide_open",
					Message: fmt.Sprintf("Service '%s' exposes port %s on all interfaces (0.0.0.0); restrict binding to specific IPs for sensitive services", svc.Name, raw),
				})
			}
		}

		hostIP := port.HostIP
		if hostIP == "" {
			parts := strings.Split(strings.Trim(raw, `"' `), ":")
			if len(parts) >= 3 {
				hostIP = parts[0]
			}
		}
		if hostIP == "127.0.0.1" || hostIP == "::1" || hostIP == "localhost" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "ipblock_loopback",
				Message: fmt.Sprintf("Service '%s' binds port %s to loopback only; verify this is intentional for container networking", svc.Name, raw),
			})
		}
	}

	if sensitive && !hasIPRestriction(svc.Environment) && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "ipblock_no_restrict",
			Message: fmt.Sprintf("Service '%s' (sensitive) exposes ports without IP restriction environment variables; consider ALLOWED_IPS or BIND_ADDRESS configuration", svc.Name),
		})
	}

	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := parts[1]
		if strings.Contains(val, "/") {
			if isPrivateRange(val) && isBroadCIDR(val) && sensitive {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "ipblock_private_exposed",
					Message: fmt.Sprintf("Service '%s' references broad private range %s in '%s'; narrow to specific subnets", svc.Name, val, parts[0]),
				})
			}
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "ipblock_wide_open":
				s.WideOpenNetworks++
			case "ipblock_private_exposed":
				s.PrivateRangeExposed++
			case "ipblock_no_restrict":
				s.MissingIPRestrict++
			case "ipblock_broad_cidr":
				s.BroadCIDRBlocks++
			case "ipblock_loopback":
				s.LoopbackExposed++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "IP Block / Allowlist Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Wide-open bindings:      %d\n", r.Summary.WideOpenNetworks)
	fmt.Fprintf(&b, "  Private range exposed:   %d\n", r.Summary.PrivateRangeExposed)
	fmt.Fprintf(&b, "  Missing IP restriction:  %d\n", r.Summary.MissingIPRestrict)
	fmt.Fprintf(&b, "  Broad CIDR blocks:       %d\n", r.Summary.BroadCIDRBlocks)
	fmt.Fprintf(&b, "  Loopback bindings:       %d\n\n", r.Summary.LoopbackExposed)
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
