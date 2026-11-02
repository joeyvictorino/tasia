package sidecar

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type SidecarType string

const (
	TypeLogging    SidecarType = "logging"
	TypeMonitoring SidecarType = "monitoring"
	TypeProxy      SidecarType = "proxy"
	TypeCustom     SidecarType = "custom"
)

type Finding struct {
	File        string `json:"file"`
	Container   string `json:"container"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ContainerInfo struct {
	Name       string      `json:"name"`
	Image      string      `json:"image"`
	Type       SidecarType `json:"type"`
	Privileged bool        `json:"privileged"`
	Volumes    []string    `json:"volumes,omitempty"`
}

type ServiceGroup struct {
	Service    string          `json:"service"`
	Main       ContainerInfo   `json:"main"`
	Sidecars   []ContainerInfo `json:"sidecars,omitempty"`
	SharedVols []string        `json:"shared_volumes,omitempty"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	SidecarCount   int `json:"sidecar_count"`
	SharedVolumes  int `json:"shared_volumes"`
	PrivEscalation int `json:"privilege_escalation"`
	TotalFindings  int `json:"total_findings"`
	Score          int `json:"score"`
}

type Report struct {
	Groups   []ServiceGroup `json:"groups"`
	Findings []Finding      `json:"findings"`
	Summary  Summary        `json:"summary"`
}

var loggingImages = []string{"fluentd", "fluent-bit", "filebeat", "logstash", "vector", "promtail"}
var monitoringImages = []string{"prometheus", "grafana", "datadog", "newrelic", "telegraf", "otel-collector", "jaeger"}
var proxyImages = []string{"envoy", "nginx", "haproxy", "traefik", "linkerd", "istio"}

func Analyze(collected *collect.Collected) Report {
	var groups []ServiceGroup
	var findings []Finding

	for _, cf := range collected.ComposeFiles {
		analyzeComposeFile(cf, &groups, &findings)
	}

	sidecarCount, sharedVolCount, privEscCount := 0, 0, 0
	for _, g := range groups {
		sidecarCount += len(g.Sidecars)
		sharedVolCount += len(g.SharedVols)
	}
	for _, f := range findings {
		if f.RuleID == "sidecar_priv_escalation" {
			privEscCount++
		}
	}

	score := 100 - privEscCount*30 - sharedVolCount*5
	if score < 0 {
		score = 0
	}

	return Report{
		Groups:   groups,
		Findings: findings,
		Summary: Summary{
			TotalServices:  len(groups),
			SidecarCount:   sidecarCount,
			SharedVolumes:  sharedVolCount,
			PrivEscalation: privEscCount,
			TotalFindings:  len(findings),
			Score:          score,
		},
	}
}

func analyzeComposeFile(cf compose.File, groups *[]ServiceGroup, findings *[]Finding) {
	for _, svc := range cf.Services {
		if svc.Image == "" {
			continue
		}

		ci := ContainerInfo{
			Name:       svc.Name,
			Image:      svc.Image,
			Type:       ClassifyImage(svc.Image),
			Privileged: svc.Privileged,
			Volumes:    extractVolNames(svc.Volumes),
		}

		group := ServiceGroup{
			Service: svc.Name,
			Main:    ci,
		}

		for _, other := range cf.Services {
			if other.Name == svc.Name || other.Image == "" {
				continue
			}
			if isSidecarOf(svc.Name, other) {
				sc := ContainerInfo{
					Name:       other.Name,
					Image:      other.Image,
					Type:       ClassifyImage(other.Image),
					Privileged: other.Privileged,
					Volumes:    extractVolNames(other.Volumes),
				}
				group.Sidecars = append(group.Sidecars, sc)

				shared := sharedVolumes(svc.Volumes, other.Volumes)
				group.SharedVols = append(group.SharedVols, shared...)

				if other.Privileged && !svc.Privileged {
					*findings = append(*findings, Finding{
						File:        cf.Path,
						Container:   other.Name,
						RuleID:      "sidecar_priv_escalation",
						Severity:    "critical",
						Detail:      fmt.Sprintf("sidecar %q is privileged but main %q is not", other.Name, svc.Name),
						Remediation: "Remove privileged mode from sidecar or add justification",
					})
				}

				if len(shared) > 0 {
					*findings = append(*findings, Finding{
						File:        cf.Path,
						Container:   other.Name,
						RuleID:      "sidecar_shared_volume",
						Severity:    "medium",
						Detail:      fmt.Sprintf("sidecar %q shares volumes with %q: %s", other.Name, svc.Name, strings.Join(shared, ", ")),
						Remediation: "Use read-only mounts for shared volumes where possible",
					})
				}

				if sc.Type == TypeCustom {
					*findings = append(*findings, Finding{
						File:        cf.Path,
						Container:   other.Name,
						RuleID:      "sidecar_unknown_type",
						Severity:    "low",
						Detail:      fmt.Sprintf("sidecar %q uses unrecognized image %q", other.Name, other.Image),
						Remediation: "Document sidecar purpose or use well-known sidecar images",
					})
				}
			}
		}

		if len(group.Sidecars) > 0 {
			*groups = append(*groups, group)
		}
	}
}

func ClassifyImage(image string) SidecarType {
	lower := strings.ToLower(image)
	for _, p := range loggingImages {
		if strings.Contains(lower, p) {
			return TypeLogging
		}
	}
	for _, p := range monitoringImages {
		if strings.Contains(lower, p) {
			return TypeMonitoring
		}
	}
	for _, p := range proxyImages {
		if strings.Contains(lower, p) {
			return TypeProxy
		}
	}
	return TypeCustom
}

func isSidecarOf(mainName string, candidate compose.Service) bool {
	if _, ok := candidate.DependsOn[mainName]; ok {
		return true
	}
	if candidate.NetworkMode == "service:"+mainName {
		return true
	}
	ctype := ClassifyImage(candidate.Image)
	if ctype == TypeLogging || ctype == TypeMonitoring || ctype == TypeProxy {
		return true
	}
	return false
}

func extractVolNames(vols []string) []string {
	var names []string
	for _, v := range vols {
		parts := strings.SplitN(v, ":", 2)
		if len(parts) > 0 {
			names = append(names, parts[0])
		}
	}
	return names
}

func sharedVolumes(a, b []string) []string {
	aSet := make(map[string]bool)
	for _, v := range extractVolNames(a) {
		aSet[v] = true
	}
	var shared []string
	for _, v := range extractVolNames(b) {
		if aSet[v] {
			shared = append(shared, v)
		}
	}
	return shared
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Sidecar Container Security Analysis\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	fmt.Fprintf(&sb, "  Service Groups:       %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Sidecar Containers:   %d\n", r.Summary.SidecarCount)
	fmt.Fprintf(&sb, "  Shared Volumes:       %d\n", r.Summary.SharedVolumes)
	fmt.Fprintf(&sb, "  Privilege Escalation: %d\n", r.Summary.PrivEscalation)
	fmt.Fprintf(&sb, "  Sidecar Score:        %d/100\n\n", r.Summary.Score)

	for _, g := range r.Groups {
		fmt.Fprintf(&sb, "  Service: %s (image: %s)\n", g.Service, g.Main.Image)
		for _, sc := range g.Sidecars {
			priv := ""
			if sc.Privileged {
				priv = " [PRIVILEGED]"
			}
			fmt.Fprintf(&sb, "    Sidecar: %s (%s, type=%s)%s\n", sc.Name, sc.Image, sc.Type, priv)
		}
		if len(g.SharedVols) > 0 {
			fmt.Fprintf(&sb, "    Shared volumes: %s\n", strings.Join(g.SharedVols, ", "))
		}
		sb.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "  %d. [%s] %s (%s)\n", i+1, f.Severity, f.Detail, f.RuleID)
			fmt.Fprintf(&sb, "     Fix: %s\n", f.Remediation)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
