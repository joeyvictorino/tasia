package configcheck

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Conflict struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	FileA    string `json:"file_a"`
	FileB    string `json:"file_b"`
	ServiceA string `json:"service_a,omitempty"`
	ServiceB string `json:"service_b,omitempty"`
}

type CheckResult struct {
	Path      string     `json:"path"`
	Conflicts []Conflict `json:"conflicts"`
	Clean     bool       `json:"clean"`
}

func CheckConflicts(collected *collect.Collected) CheckResult {
	var conflicts []Conflict

	conflicts = append(conflicts, checkPortConflicts(collected)...)
	conflicts = append(conflicts, checkNameConflicts(collected)...)
	conflicts = append(conflicts, checkNetworkCollisions(collected)...)
	conflicts = append(conflicts, checkVolumeOverlaps(collected)...)
	conflicts = append(conflicts, checkEnvConflicts(collected)...)

	sort.Slice(conflicts, func(i, j int) bool {
		return severityRank(conflicts[i].Severity) > severityRank(conflicts[j].Severity)
	})

	return CheckResult{
		Path:      collected.Root,
		Conflicts: conflicts,
		Clean:     len(conflicts) == 0,
	}
}

func checkPortConflicts(collected *collect.Collected) []Conflict {
	type portKey struct {
		hostPort int
		hostIP   string
	}
	type portOwner struct {
		service string
		file    string
	}
	seen := map[portKey]portOwner{}
	var conflicts []Conflict

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
				key := portKey{hostPort: p.HostPort, hostIP: ip}
				if prev, ok := seen[key]; ok {
					if prev.service != svc.Name || prev.file != cf.Path {
						conflicts = append(conflicts, Conflict{
							Type:     "port_conflict",
							Severity: "high",
							Message:  fmt.Sprintf("Host port %d (%s) claimed by both %s and %s", p.HostPort, ip, prev.service, svc.Name),
							FileA:    prev.file,
							FileB:    cf.Path,
							ServiceA: prev.service,
							ServiceB: svc.Name,
						})
					}
				} else {
					seen[key] = portOwner{service: svc.Name, file: cf.Path}
				}
			}
		}
	}
	return conflicts
}

func checkNameConflicts(collected *collect.Collected) []Conflict {
	type nameOwner struct {
		file string
	}
	seen := map[string]nameOwner{}
	var conflicts []Conflict

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			if prev, ok := seen[svc.Name]; ok {
				if prev.file != cf.Path {
					conflicts = append(conflicts, Conflict{
						Type:     "name_conflict",
						Severity: "high",
						Message:  fmt.Sprintf("Service name %q defined in multiple compose files", svc.Name),
						FileA:    prev.file,
						FileB:    cf.Path,
						ServiceA: svc.Name,
						ServiceB: svc.Name,
					})
				}
			} else {
				seen[svc.Name] = nameOwner{file: cf.Path}
			}
		}
	}
	return conflicts
}

func checkNetworkCollisions(collected *collect.Collected) []Conflict {
	type netOwner struct {
		file string
	}
	seen := map[string]netOwner{}
	var conflicts []Conflict

	for _, cf := range collected.ComposeFiles {
		for name := range cf.Networks {
			if prev, ok := seen[name]; ok {
				if prev.file != cf.Path {
					conflicts = append(conflicts, Conflict{
						Type:     "network_collision",
						Severity: "medium",
						Message:  fmt.Sprintf("Network %q defined in multiple compose files", name),
						FileA:    prev.file,
						FileB:    cf.Path,
					})
				}
			} else {
				seen[name] = netOwner{file: cf.Path}
			}
		}
	}
	return conflicts
}

func checkVolumeOverlaps(collected *collect.Collected) []Conflict {
	type volOwner struct {
		service string
		file    string
		target  string
	}
	seen := map[string]volOwner{}
	var conflicts []Conflict

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			for _, v := range svc.Volumes {
				parts := strings.SplitN(v, ":", 2)
				if len(parts) < 2 {
					continue
				}
				hostPath := parts[0]
				if !strings.HasPrefix(hostPath, "/") && !strings.HasPrefix(hostPath, ".") {
					continue
				}
				if prev, ok := seen[hostPath]; ok {
					if prev.service != svc.Name || prev.file != cf.Path {
						if prev.target != parts[1] {
							conflicts = append(conflicts, Conflict{
								Type:     "volume_overlap",
								Severity: "medium",
								Message:  fmt.Sprintf("Host path %q mounted to different targets: %s (%s) and %s (%s)", hostPath, prev.target, prev.service, parts[1], svc.Name),
								FileA:    prev.file,
								FileB:    cf.Path,
								ServiceA: prev.service,
								ServiceB: svc.Name,
							})
						}
					}
				} else {
					seen[hostPath] = volOwner{service: svc.Name, file: cf.Path, target: parts[1]}
				}
			}
		}
	}
	return conflicts
}

func checkEnvConflicts(collected *collect.Collected) []Conflict {
	type envOwner struct {
		service string
		file    string
		value   string
	}
	seen := map[string]envOwner{}
	var conflicts []Conflict

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			for _, e := range svc.Environment {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) < 2 {
					continue
				}
				key := svc.Name + ":" + parts[0]
				if prev, ok := seen[key]; ok {
					if prev.value != parts[1] {
						conflicts = append(conflicts, Conflict{
							Type:     "env_conflict",
							Severity: "low",
							Message:  fmt.Sprintf("Environment variable %s has different values for service %s", parts[0], svc.Name),
							FileA:    prev.file,
							FileB:    cf.Path,
							ServiceA: svc.Name,
							ServiceB: svc.Name,
						})
					}
				} else {
					seen[key] = envOwner{service: svc.Name, file: cf.Path, value: parts[1]}
				}
			}
		}
	}
	return conflicts
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func FormatText(r CheckResult) string {
	if r.Clean {
		return fmt.Sprintf("Config Check: %s — no conflicts found\n", r.Path)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Config Check: %s — %d conflict(s) found\n\n", r.Path, len(r.Conflicts))
	for i, c := range r.Conflicts {
		fmt.Fprintf(&b, "  %d. [%s] %s (%s)\n", i+1, strings.ToUpper(c.Severity), c.Message, c.Type)
		fmt.Fprintf(&b, "     files: %s, %s\n", c.FileA, c.FileB)
		if c.ServiceA != "" {
			fmt.Fprintf(&b, "     services: %s, %s\n", c.ServiceA, c.ServiceB)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
