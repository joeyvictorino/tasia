// Package compose parses Docker Compose files using yaml.v3 nodes for
// accurate line numbers. It extracts service definitions, published
// ports, volumes, environment variables, network configuration and
// restart policies without evaluating or interpolating variable
// references.
package compose

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// File represents parsed compose with line info.
type File struct {
	Path     string
	Content  string
	Services []Service
	Networks map[string]Network
	// Raw node kept for advanced line queries if needed
	root *yaml.Node
}

// Service holds name + relevant fields with lines where possible.
type Service struct {
	Name            string
	Image           string
	ImageLine       int
	Ports           []PortMapping
	PortsLine       int // line of the 'ports:' key if present
	Volumes         []string
	VolumesLine     int // line of the 'volumes:' key if present
	Privileged      bool
	PrivLine        int
	Environment     []string // "KEY=val" entries (from map or list form)
	EnvLine         int      // line of the 'environment:' key if present
	NetworkMode     string // value of network_mode: (e.g. "host")
	NetworkModeLine int
	Restart         string // value of restart: (e.g. "always", "unless-stopped")
	RestartLine     int
	CapAdd          []string
	CapAddLine      int
	CapDrop         []string
	CapDropLine     int
	SecurityOpt     []string
	SecurityOptLine int
	// Healthcheck fields
	Healthcheck     *Healthcheck
	HealthcheckLine int
	// Logging fields
	Logging     *LoggingConfig
	LoggingLine int
	// Resource limit fields
	MemLimit       string
	MemLimitLine   int
	MemReservation string
	MemResLine     int
	CPUs           string
	CPUsLine       int
	PidsLimit      int
	PidsLimitLine  int
	ReadOnly       bool
	ReadOnlyLine   int
	// Tmpfs fields
	Tmpfs     []string
	TmpfsLine int
	// DNS fields
	DNS          []string
	DNSLine      int
	DNSSearch    []string
	DNSSearchLine int
	// User namespace mode
	UsernsMode     string
	UsernsModeLine int
	// Labels
	Labels    map[string]string
	LabelsLine int
}

// Healthcheck represents the healthcheck block in a compose service.
type Healthcheck struct {
	Test        []string
	Interval    string
	Timeout     string
	Retries     int
	StartPeriod string
	Disable     bool
}

// LoggingConfig represents the logging block in a compose service.
type LoggingConfig struct {
	Driver  string
	Options map[string]string
}

type PortMapping struct {
	HostPort   int
	TargetPort int
	Raw        string // original "11434:11434" or "127.0.0.1:..."
	HostIP     string // explicit host IP (long-form host_ip:, or derived from short form)
	Line       int
}

// IsAllInterfaces reports whether the published port is reachable on all host
// interfaces (0.0.0.0) rather than bound to localhost. Handles both the short
// form "127.0.0.1:3000:8080" and the long form with an explicit host_ip.
func (p PortMapping) IsAllInterfaces() bool {
	ip := p.HostIP
	if ip == "" {
		parts := strings.Split(strings.Trim(p.Raw, `"' `), ":")
		if len(parts) >= 3 { // ip:host:container
			ip = parts[0]
		}
	}
	switch strings.TrimSpace(ip) {
	case "127.0.0.1", "localhost", "::1":
		return false
	default:
		// empty (no bind = all interfaces), 0.0.0.0, ::, or a specific LAN IP
		return true
	}
}

type Network struct {
	Internal bool
	Line     int
}

// Parse reads compose and extracts using yaml nodes to preserve line numbers.
func Parse(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(b)

	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}

	f := &File{
		Path:    path,
		Content: content,
		root:    &root,
	}

	// Find the document node
	doc := &root
	if len(root.Content) > 0 {
		doc = root.Content[0]
	}

	// services map is under key "services"
	servicesNode := getMapValue(doc, "services")
	if servicesNode != nil && servicesNode.Kind == yaml.MappingNode {
		for i := 0; i < len(servicesNode.Content); i += 2 {
			nameNode := servicesNode.Content[i]
			svcNode := servicesNode.Content[i+1]
			svc := Service{Name: nameNode.Value}
			// image
			imgNode := getMapValue(svcNode, "image")
			if imgNode != nil {
				svc.Image = imgNode.Value
				svc.ImageLine = imgNode.Line
			}
			// ports
			portsNode := getMapValue(svcNode, "ports")
			if portsNode != nil {
				svc.PortsLine = portsNode.Line
				for _, pnode := range portsNode.Content {
					pm := parsePort(pnode)
					if pm != nil {
						svc.Ports = append(svc.Ports, *pm)
					}
				}
			}
			// privileged
			privNode := getMapValue(svcNode, "privileged")
			if privNode != nil && (privNode.Value == "true" || privNode.Value == "yes") {
				svc.Privileged = true
				svc.PrivLine = privNode.Line
			}
			// network_mode: (e.g. host) — a service on the host network publishes
			// its ports on all interfaces without any ports: mapping.
			nmNode := getMapValue(svcNode, "network_mode")
			if nmNode != nil {
				svc.NetworkMode = strings.Trim(nmNode.Value, `"' `)
				svc.NetworkModeLine = nmNode.Line
			}
			// userns_mode
			unsNode := getMapValue(svcNode, "userns_mode")
			if unsNode != nil {
				svc.UsernsMode = strings.Trim(unsNode.Value, `"' `)
				svc.UsernsModeLine = unsNode.Line
			}
			// restart
			restartNode := getMapValue(svcNode, "restart")
			if restartNode != nil {
				svc.Restart = strings.Trim(restartNode.Value, `"' `)
				svc.RestartLine = restartNode.Line
			}
			// volumes for broad mounts / docker.sock — handle both short form
			// ("host:container[:mode]") and long form (type/source/target maps).
			volsNode := getMapValue(svcNode, "volumes")
			if volsNode != nil {
				svc.VolumesLine = volsNode.Line
				for _, v := range volsNode.Content {
					if v.Kind == yaml.MappingNode {
						src := getScalar(v, "source")
						tgt := getScalar(v, "target")
						ro := getScalar(v, "read_only")
						entry := src + ":" + tgt
						if ro == "true" {
							entry += ":ro"
						}
						svc.Volumes = append(svc.Volumes, entry)
					} else {
						svc.Volumes = append(svc.Volumes, v.Value)
					}
				}
			}
			// environment: for CORS checks + secret key names (values not retained long-term)
			envNode := getMapValue(svcNode, "environment")
			if envNode != nil {
				svc.EnvLine = envNode.Line
				if envNode.Kind == yaml.MappingNode {
					for i := 0; i < len(envNode.Content); i += 2 {
						k := envNode.Content[i].Value
						v := envNode.Content[i+1].Value
						svc.Environment = append(svc.Environment, k+"="+v)
					}
				} else if envNode.Kind == yaml.SequenceNode {
					for _, e := range envNode.Content {
						svc.Environment = append(svc.Environment, e.Value)
					}
				}
			}
			// cap_add
			capAddNode := getMapValue(svcNode, "cap_add")
			if capAddNode != nil {
				svc.CapAddLine = capAddNode.Line
				for _, c := range capAddNode.Content {
					svc.CapAdd = append(svc.CapAdd, strings.ToUpper(strings.TrimSpace(c.Value)))
				}
			}
			// cap_drop
			capDropNode := getMapValue(svcNode, "cap_drop")
			if capDropNode != nil {
				svc.CapDropLine = capDropNode.Line
				for _, c := range capDropNode.Content {
					svc.CapDrop = append(svc.CapDrop, strings.ToUpper(strings.TrimSpace(c.Value)))
				}
			}
			// security_opt
			secOptNode := getMapValue(svcNode, "security_opt")
			if secOptNode != nil {
				svc.SecurityOptLine = secOptNode.Line
				for _, s := range secOptNode.Content {
					svc.SecurityOpt = append(svc.SecurityOpt, s.Value)
				}
			}
			// healthcheck
			hcNode := getMapValue(svcNode, "healthcheck")
			if hcNode != nil {
				svc.HealthcheckLine = hcNode.Line
				hc := &Healthcheck{}
				testNode := getMapValue(hcNode, "test")
				if testNode != nil {
					if testNode.Kind == yaml.SequenceNode {
						for _, t := range testNode.Content {
							hc.Test = append(hc.Test, t.Value)
						}
					} else {
						hc.Test = []string{"CMD-SHELL", testNode.Value}
					}
				}
				if v := getScalar(hcNode, "interval"); v != "" {
					hc.Interval = v
				}
				if v := getScalar(hcNode, "timeout"); v != "" {
					hc.Timeout = v
				}
				if v := getScalar(hcNode, "start_period"); v != "" {
					hc.StartPeriod = v
				}
				if v := getScalar(hcNode, "retries"); v != "" {
					if n, ok := atoiSafe(v); ok {
						hc.Retries = n
					}
				}
				disNode := getMapValue(hcNode, "disable")
				if disNode != nil && (disNode.Value == "true" || disNode.Value == "yes") {
					hc.Disable = true
				}
				if len(hc.Test) > 0 && len(hc.Test) == 1 && hc.Test[0] == "NONE" {
					hc.Disable = true
				}
				svc.Healthcheck = hc
			}
			// logging
			logNode := getMapValue(svcNode, "logging")
			if logNode != nil {
				svc.LoggingLine = logNode.Line
				lc := &LoggingConfig{Options: map[string]string{}}
				if d := getScalar(logNode, "driver"); d != "" {
					lc.Driver = d
				}
				optNode := getMapValue(logNode, "options")
				if optNode != nil && optNode.Kind == yaml.MappingNode {
					for j := 0; j < len(optNode.Content); j += 2 {
						lc.Options[optNode.Content[j].Value] = optNode.Content[j+1].Value
					}
				}
				svc.Logging = lc
			}
			// mem_limit
			mlNode := getMapValue(svcNode, "mem_limit")
			if mlNode != nil {
				svc.MemLimit = mlNode.Value
				svc.MemLimitLine = mlNode.Line
			}
			// mem_reservation
			mrNode := getMapValue(svcNode, "mem_reservation")
			if mrNode != nil {
				svc.MemReservation = mrNode.Value
				svc.MemResLine = mrNode.Line
			}
			// cpus
			cpuNode := getMapValue(svcNode, "cpus")
			if cpuNode != nil {
				svc.CPUs = cpuNode.Value
				svc.CPUsLine = cpuNode.Line
			}
			// pids_limit
			pidsNode := getMapValue(svcNode, "pids_limit")
			if pidsNode != nil {
				if n, ok := atoiSafe(pidsNode.Value); ok {
					svc.PidsLimit = n
				}
				svc.PidsLimitLine = pidsNode.Line
			}
			// read_only
			roNode := getMapValue(svcNode, "read_only")
			if roNode != nil && (roNode.Value == "true" || roNode.Value == "yes") {
				svc.ReadOnly = true
				svc.ReadOnlyLine = roNode.Line
			}
			// deploy.resources (v3 format)
			deployNode := getMapValue(svcNode, "deploy")
			if deployNode != nil {
				resNode := getMapValue(deployNode, "resources")
				if resNode != nil {
					limNode := getMapValue(resNode, "limits")
					if limNode != nil {
						if svc.MemLimit == "" {
							if v := getScalar(limNode, "memory"); v != "" {
								svc.MemLimit = v
							}
						}
						if svc.CPUs == "" {
							if v := getScalar(limNode, "cpus"); v != "" {
								svc.CPUs = v
							}
						}
						if svc.PidsLimit == 0 {
							if v := getScalar(limNode, "pids"); v != "" {
								if n, ok := atoiSafe(v); ok {
									svc.PidsLimit = n
								}
							}
						}
					}
					resrvNode := getMapValue(resNode, "reservations")
					if resrvNode != nil && svc.MemReservation == "" {
						if v := getScalar(resrvNode, "memory"); v != "" {
							svc.MemReservation = v
						}
					}
				}
			}
			// dns
			dnsNode := getMapValue(svcNode, "dns")
			if dnsNode != nil {
				svc.DNSLine = dnsNode.Line
				if dnsNode.Kind == yaml.SequenceNode {
					for _, d := range dnsNode.Content {
						svc.DNS = append(svc.DNS, d.Value)
					}
				} else {
					svc.DNS = append(svc.DNS, dnsNode.Value)
				}
			}
			// dns_search
			dnsSearchNode := getMapValue(svcNode, "dns_search")
			if dnsSearchNode != nil {
				svc.DNSSearchLine = dnsSearchNode.Line
				if dnsSearchNode.Kind == yaml.SequenceNode {
					for _, d := range dnsSearchNode.Content {
						svc.DNSSearch = append(svc.DNSSearch, d.Value)
					}
				} else {
					svc.DNSSearch = append(svc.DNSSearch, dnsSearchNode.Value)
				}
			}
			// labels
			labelsNode := getMapValue(svcNode, "labels")
			if labelsNode != nil {
				svc.LabelsLine = labelsNode.Line
				svc.Labels = map[string]string{}
				if labelsNode.Kind == yaml.MappingNode {
					for j := 0; j < len(labelsNode.Content); j += 2 {
						svc.Labels[labelsNode.Content[j].Value] = labelsNode.Content[j+1].Value
					}
				} else if labelsNode.Kind == yaml.SequenceNode {
					for _, l := range labelsNode.Content {
						if idx := strings.Index(l.Value, "="); idx > 0 {
							svc.Labels[l.Value[:idx]] = l.Value[idx+1:]
						} else {
							svc.Labels[l.Value] = ""
						}
					}
				}
			}
			// tmpfs
			tmpfsNode := getMapValue(svcNode, "tmpfs")
			if tmpfsNode != nil {
				svc.TmpfsLine = tmpfsNode.Line
				if tmpfsNode.Kind == yaml.SequenceNode {
					for _, t := range tmpfsNode.Content {
						svc.Tmpfs = append(svc.Tmpfs, t.Value)
					}
				} else {
					svc.Tmpfs = append(svc.Tmpfs, tmpfsNode.Value)
				}
			}
			f.Services = append(f.Services, svc)
		}
	}

	// networks
	netsNode := getMapValue(doc, "networks")
	if netsNode != nil {
		f.Networks = map[string]Network{}
		for i := 0; i < len(netsNode.Content); i += 2 {
			netName := netsNode.Content[i].Value
			netNode := netsNode.Content[i+1]
			n := Network{}
			intNode := getMapValue(netNode, "internal")
			if intNode != nil && (intNode.Value == "true" || intNode.Value == "yes") {
				n.Internal = true
			}
			n.Line = netsNode.Content[i].Line
			f.Networks[netName] = n
		}
	}

	return f, nil
}

// getScalar returns the string value of a scalar child under key, or "".
func getScalar(node *yaml.Node, key string) string {
	if v := getMapValue(node, key); v != nil {
		return v.Value
	}
	return ""
}

func getMapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func parsePort(node *yaml.Node) *PortMapping {
	if node == nil {
		return nil
	}
	line := node.Line
	clean := func(s string) string { return strings.Trim(s, `"' `) }

	// Handle long-form map ports:
	// - target: 8080
	//   published: "127.0.0.1:3000"
	// or
	// - published: 3000
	//   target: 8080
	if node.Kind == yaml.MappingNode {
		pubNode := getMapValue(node, "published")
		tgtNode := getMapValue(node, "target")
		hostIP := getScalar(node, "host_ip")
		var raw string
		var hp, tp int
		if pubNode != nil {
			raw = pubNode.Value
			pv := clean(pubNode.Value)
			pparts := splitPortRaw(pv)
			if len(pparts) == 1 {
				if n, ok := atoiSafe(pparts[0]); ok {
					hp = n
				}
			} else if len(pparts) >= 2 {
				// ip:port or port:something
				last := clean(pparts[len(pparts)-1])
				if n, ok := atoiSafe(last); ok {
					hp = n
				}
			}
		}
		if tgtNode != nil {
			if n, ok := atoiSafe(clean(tgtNode.Value)); ok {
				tp = n
			}
		}
		return &PortMapping{Raw: raw, Line: line, HostPort: hp, TargetPort: tp, HostIP: clean(hostIP)}
	}

	// scalar / short form
	raw := node.Value
	if raw == "" && len(node.Content) > 0 {
		raw = node.Value
	}
	if raw == "" {
		return nil
	}
	pm := &PortMapping{Raw: raw, Line: line}
	parts := splitPortRaw(raw)
	if len(parts) == 1 {
		p := clean(parts[0])
		if n, ok := atoiSafe(p); ok {
			pm.HostPort = n
			pm.TargetPort = n
		}
	} else if len(parts) >= 2 {
		first := clean(parts[0])
		second := clean(parts[1])
		last := clean(parts[len(parts)-1])
		if strings.Contains(first, ".") || strings.Contains(first, ":") {
			if n, ok := atoiSafe(second); ok {
				pm.HostPort = n
			}
			if n, ok := atoiSafe(last); ok {
				pm.TargetPort = n
			}
		} else {
			if n, ok := atoiSafe(first); ok {
				pm.HostPort = n
			}
			if n, ok := atoiSafe(last); ok {
				pm.TargetPort = n
			}
		}
	}
	return pm
}

func splitPortRaw(s string) []string {
	// handle ip:port:port or port:port
	s = strings.Trim(s, " \t")
	if idx := strings.IndexAny(s, " "); idx >= 0 {
		s = s[:idx]
	}
	// remove protocol suffix
	if i := strings.LastIndex(s, "/"); i > 0 {
		s = s[:i]
	}
	return strings.Split(s, ":")
}

func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}
