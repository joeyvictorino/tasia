package servicemesh

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type MeshFinding struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Summary struct {
	TotalServices int    `json:"total_services"`
	MeshDetected  bool   `json:"mesh_detected"`
	MeshType      string `json:"mesh_type,omitempty"`
	Findings      int    `json:"findings"`
	HighSev       int    `json:"high_severity"`
	MediumSev     int    `json:"medium_severity"`
	LowSev        int    `json:"low_severity"`
	Score         int    `json:"score"`
	Grade         string `json:"grade"`
}

type Report struct {
	Findings []MeshFinding `json:"findings"`
	Summary  Summary       `json:"summary"`
}

var meshImages = map[string]string{
	"istio":     "istio",
	"envoy":     "istio",
	"linkerd":   "linkerd",
	"consul":    "consul",
	"traefik":   "traefik-mesh",
}

var sidecarImages = []string{
	"istio/proxyv2", "envoyproxy/envoy",
	"linkerd-proxy", "linkerd/proxy",
	"consul-connect", "hashicorp/consul",
}

func Analyze(collected *collect.Collected) Report {
	var findings []MeshFinding
	meshType := ""
	serviceCount := 0

	for _, cf := range collected.ComposeFiles {
		serviceCount += len(cf.Services)
		for _, svc := range cf.Services {
			mt := detectMeshType(svc)
			if mt != "" && meshType == "" {
				meshType = mt
			}

			findings = append(findings, checkMTLS(svc)...)
			findings = append(findings, checkSidecarInjection(svc, cf.Services)...)
			findings = append(findings, checkNetworkPolicy(svc)...)
			findings = append(findings, checkMeshConfig(svc)...)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		si, sj := sevOrd(findings[i].Severity), sevOrd(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return findings[i].Service < findings[j].Service
	})

	high, med, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}

	score := 100 - high*15 - med*5 - low*2
	if score < 0 {
		score = 0
	}

	return Report{
		Findings: findings,
		Summary: Summary{
			TotalServices: serviceCount,
			MeshDetected:  meshType != "",
			MeshType:      meshType,
			Findings:      len(findings),
			HighSev:       high,
			MediumSev:     med,
			LowSev:        low,
			Score:         score,
			Grade:         scoreGrade(score),
		},
	}
}

func detectMeshType(svc compose.Service) string {
	img := strings.ToLower(svc.Image)
	for pattern, meshName := range meshImages {
		if strings.Contains(img, pattern) {
			return meshName
		}
	}
	for _, label := range flatLabels(svc) {
		lower := strings.ToLower(label)
		if strings.Contains(lower, "istio") {
			return "istio"
		}
		if strings.Contains(lower, "linkerd") {
			return "linkerd"
		}
	}
	return ""
}

func checkMTLS(svc compose.Service) []MeshFinding {
	var findings []MeshFinding
	for _, entry := range svc.Environment {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.ToLower(parts[1])

		if strings.Contains(key, "mtls") && (val == "false" || val == "disable" || val == "permissive") {
			findings = append(findings, MeshFinding{
				Service:  svc.Name,
				Category: "mtls",
				Severity: "high",
				Message:  fmt.Sprintf("mTLS is disabled or permissive via %s=%s", parts[0], parts[1]),
			})
		}
		if strings.Contains(key, "tls_mode") && val == "disable" {
			findings = append(findings, MeshFinding{
				Service:  svc.Name,
				Category: "mtls",
				Severity: "high",
				Message:  fmt.Sprintf("TLS mode disabled via %s=%s", parts[0], parts[1]),
			})
		}
	}
	return findings
}

func checkSidecarInjection(svc compose.Service, allSvcs []compose.Service) []MeshFinding {
	var findings []MeshFinding

	hasMesh := false
	for _, s := range allSvcs {
		if isMeshProxy(s) {
			hasMesh = true
			break
		}
	}

	if !hasMesh {
		return nil
	}

	if !isMeshProxy(svc) && !hasSidecarLabel(svc) {
		findings = append(findings, MeshFinding{
			Service:  svc.Name,
			Category: "sidecar",
			Severity: "medium",
			Message:  "Service has no mesh sidecar injection label in a mesh-enabled stack",
		})
	}

	for _, label := range flatLabels(svc) {
		lower := strings.ToLower(label)
		if strings.Contains(lower, "sidecar.istio.io/inject") && strings.Contains(lower, "false") {
			findings = append(findings, MeshFinding{
				Service:  svc.Name,
				Category: "sidecar",
				Severity: "high",
				Message:  "Sidecar injection explicitly disabled",
			})
		}
	}

	return findings
}

func checkNetworkPolicy(svc compose.Service) []MeshFinding {
	var findings []MeshFinding
	if svc.NetworkMode == "host" && isMeshProxy(svc) {
		findings = append(findings, MeshFinding{
			Service:  svc.Name,
			Category: "network",
			Severity: "high",
			Message:  "Mesh proxy running with network_mode: host bypasses network isolation",
		})
	}
	return findings
}

func checkMeshConfig(svc compose.Service) []MeshFinding {
	var findings []MeshFinding

	for _, entry := range svc.Environment {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.ToLower(parts[1])

		if strings.Contains(key, "access_log") && (val == "false" || val == "off" || val == "") {
			findings = append(findings, MeshFinding{
				Service:  svc.Name,
				Category: "observability",
				Severity: "medium",
				Message:  "Access logging disabled for mesh proxy",
			})
		}
		if strings.Contains(key, "tracing") && (val == "false" || val == "off") {
			findings = append(findings, MeshFinding{
				Service:  svc.Name,
				Category: "observability",
				Severity: "low",
				Message:  "Distributed tracing disabled",
			})
		}
	}

	return findings
}

func isMeshProxy(svc compose.Service) bool {
	img := strings.ToLower(svc.Image)
	for _, pattern := range sidecarImages {
		if strings.Contains(img, pattern) {
			return true
		}
	}
	return false
}

func hasSidecarLabel(svc compose.Service) bool {
	for _, label := range flatLabels(svc) {
		lower := strings.ToLower(label)
		if strings.Contains(lower, "sidecar") || strings.Contains(lower, "inject") {
			return true
		}
	}
	return false
}

func flatLabels(svc compose.Service) []string {
	var out []string
	for k, v := range svc.Labels {
		out = append(out, k+"="+v)
	}
	return out
}

func sevOrd(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func scoreGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Service Mesh Configuration Audit\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Services:      %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Mesh detected: %v\n", r.Summary.MeshDetected)
	if r.Summary.MeshType != "" {
		fmt.Fprintf(&sb, "  Mesh type:     %s\n", r.Summary.MeshType)
	}
	fmt.Fprintf(&sb, "  Findings:      %d\n", r.Summary.Findings)
	fmt.Fprintf(&sb, "  High:          %d\n", r.Summary.HighSev)
	fmt.Fprintf(&sb, "  Medium:        %d\n", r.Summary.MediumSev)
	fmt.Fprintf(&sb, "  Low:           %d\n", r.Summary.LowSev)
	fmt.Fprintf(&sb, "  Score:         %d/100 (%s)\n\n", r.Summary.Score, r.Summary.Grade)

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "  %d. [%s] %s: %s (%s)\n",
				i+1, strings.ToUpper(f.Severity), f.Service, f.Message, f.Category)
		}
	}

	return sb.String()
}
