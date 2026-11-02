package socketperm

import (
	"fmt"
	"math"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Service     string `json:"service"`
	Socket      string `json:"socket"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type Report struct {
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

type Summary struct {
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"by_severity"`
	ByRule      map[string]int `json:"by_rule"`
	Services    int            `json:"services_affected"`
}

var dockerSocketPaths = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/dockershim.sock",
}

var runtimeSocketPaths = []string{
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/run/crio/crio.sock",
}

var sensitiveSocketPaths = []string{
	"/var/run/dbus/system_bus_socket",
	"/run/dbus/system_bus_socket",
	"/tmp/.X11-unix",
	"/var/run/nscd/socket",
}

func Analyze(c *collect.Collected) Report {
	var findings []Finding

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, vol := range svc.Volumes {
				src := volumeSource(vol)
				findings = append(findings, checkDockerSocket(svc.Name, src)...)
				findings = append(findings, checkRuntimeSocket(svc.Name, src)...)
				findings = append(findings, checkSensitiveSocket(svc.Name, src)...)
				findings = append(findings, checkWritableSocket(svc.Name, vol)...)
			}
		}
	}

	r := Report{Findings: findings}
	r.Summary = buildSummary(findings)
	return r
}

func checkDockerSocket(service, src string) []Finding {
	for _, sock := range dockerSocketPaths {
		if src == sock {
			return []Finding{{
				RuleID:      "socket_docker_mount",
				Severity:    "critical",
				Service:     service,
				Socket:      src,
				Description: "Docker socket mounted into container grants full host control",
				Remediation: "Remove Docker socket mount; use a Docker API proxy with restricted permissions",
			}}
		}
	}
	return nil
}

func checkRuntimeSocket(service, src string) []Finding {
	for _, sock := range runtimeSocketPaths {
		if src == sock {
			return []Finding{{
				RuleID:      "socket_runtime_mount",
				Severity:    "high",
				Service:     service,
				Socket:      src,
				Description: "Container runtime socket mounted; may allow container escape",
				Remediation: "Remove runtime socket mount; use purpose-specific APIs instead",
			}}
		}
	}
	return nil
}

func checkSensitiveSocket(service, src string) []Finding {
	for _, sock := range sensitiveSocketPaths {
		if src == sock || strings.HasPrefix(src, sock) {
			return []Finding{{
				RuleID:      "socket_sensitive_mount",
				Severity:    "medium",
				Service:     service,
				Socket:      src,
				Description: "Sensitive system socket mounted into container",
				Remediation: "Remove socket mount unless required; use read-only mount if needed",
			}}
		}
	}
	return nil
}

func checkWritableSocket(service, vol string) []Finding {
	src := volumeSource(vol)
	if !strings.HasSuffix(src, ".sock") && !strings.HasSuffix(src, ".socket") {
		return nil
	}
	if isReadOnly(vol) {
		return nil
	}
	for _, sock := range dockerSocketPaths {
		if src == sock {
			return nil
		}
	}
	for _, sock := range runtimeSocketPaths {
		if src == sock {
			return nil
		}
	}
	for _, sock := range sensitiveSocketPaths {
		if src == sock {
			return nil
		}
	}
	return []Finding{{
		RuleID:      "socket_writable_mount",
		Severity:    "medium",
		Service:     service,
		Socket:      src,
		Description: "Unix socket mounted read-write into container",
		Remediation: "Mount socket read-only (:ro) if write access is not required",
	}}
}

func volumeSource(vol string) string {
	parts := strings.SplitN(vol, ":", 2)
	return parts[0]
}

func isReadOnly(vol string) bool {
	parts := strings.Split(vol, ":")
	for _, p := range parts {
		if p == "ro" {
			return true
		}
	}
	return false
}

func buildSummary(findings []Finding) Summary {
	s := Summary{
		Total:      len(findings),
		BySeverity: map[string]int{},
		ByRule:     map[string]int{},
	}
	services := map[string]bool{}
	for _, f := range findings {
		s.BySeverity[f.Severity]++
		s.ByRule[f.RuleID]++
		services[f.Service] = true
	}
	s.Services = len(services)
	return s
}

func Score(r Report) float64 {
	if r.Summary.Total == 0 {
		return 100
	}
	penalty := 0.0
	for _, f := range r.Findings {
		switch f.Severity {
		case "critical":
			penalty += 40
		case "high":
			penalty += 25
		case "medium":
			penalty += 10
		}
	}
	return math.Max(0, 100-penalty)
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Socket Permission Audit (%d findings)\n\n", r.Summary.Total)
	if r.Summary.Total == 0 {
		b.WriteString("  No socket security issues detected.\n")
		return b.String()
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s  service=%s  socket=%s\n", f.Severity, f.RuleID, f.Service, f.Socket)
		fmt.Fprintf(&b, "    %s\n", f.Description)
		fmt.Fprintf(&b, "    fix: %s\n\n", f.Remediation)
	}
	fmt.Fprintf(&b, "  Score: %.0f/100  (%d services affected)\n", Score(r), r.Summary.Services)
	return b.String()
}
