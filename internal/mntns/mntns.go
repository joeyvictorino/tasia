package mntns

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	ReadOnly bool      `json:"read_only"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	RootFSMount       int `json:"rootfs_mount"`
	DockerSockMount   int `json:"docker_sock_mount"`
	SensitiveMount    int `json:"sensitive_mount"`
	WritableHostMount int `json:"writable_host_mount"`
	NoReadOnlyRoot    int `json:"no_read_only_root"`
	TotalFindings     int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var sensitivePaths = []string{
	"/etc", "/proc", "/sys", "/var/run", "/run",
	"/root", "/home", "/boot", "/dev",
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult
	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			sr := analyzeService(&cf.Services[i], cf.Path)
			services = append(services, sr)
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		for _, f := range s.Findings {
			switch f.RuleID {
			case "mntns_rootfs_mount":
				summary.RootFSMount++
			case "mntns_docker_sock":
				summary.DockerSockMount++
			case "mntns_sensitive_mount":
				summary.SensitiveMount++
			case "mntns_writable_host":
				summary.WritableHostMount++
			case "mntns_no_readonly_root":
				summary.NoReadOnlyRoot++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:     svc.Name,
		File:     file,
		ReadOnly: svc.ReadOnly,
	}

	for _, vol := range svc.Volumes {
		hostPath, _, readOnly := parseVolume(vol)
		if hostPath == "" {
			continue
		}

		lower := strings.ToLower(hostPath)

		if hostPath == "/" {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "mntns_rootfs_mount",
				Severity:    "critical",
				Detail:      fmt.Sprintf("Host root filesystem '/' mounted into container via '%s' — full host filesystem access", vol),
				Remediation: "Mount only the specific subdirectories needed; never mount the entire root filesystem",
			})
			continue
		}

		if lower == "/var/run/docker.sock" || lower == "/run/docker.sock" {
			sev := "critical"
			if readOnly {
				sev = "high"
			}
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "mntns_docker_sock",
				Severity:    sev,
				Detail:      fmt.Sprintf("Docker socket mounted via '%s' — container can control Docker daemon", vol),
				Remediation: "Remove Docker socket mount; use Docker-in-Docker or rootless alternatives if Docker access is needed",
			})
			continue
		}

		for _, sp := range sensitivePaths {
			if strings.EqualFold(hostPath, sp) || strings.HasPrefix(lower, strings.ToLower(sp)+"/") {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "mntns_sensitive_mount",
					Severity:    "high",
					Detail:      fmt.Sprintf("Sensitive host path '%s' mounted via '%s' — container can access host system files", hostPath, vol),
					Remediation: fmt.Sprintf("Remove mount of '%s' or mount a specific subdirectory with read-only access", hostPath),
				})
				break
			}
		}

		if !readOnly && isAbsoluteHostPath(hostPath) {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "mntns_writable_host",
				Severity:    "medium",
				Detail:      fmt.Sprintf("Host path '%s' mounted writable via '%s' — container can modify host files", hostPath, vol),
				Remediation: fmt.Sprintf("Add :ro flag to mount '%s' read-only if write access is not required", hostPath),
			})
		}
	}

	if !svc.ReadOnly && !svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "mntns_no_readonly_root",
			Severity:    "low",
			Detail:      "Container root filesystem is writable — malicious processes can modify container files",
			Remediation: "Set read_only: true and use tmpfs mounts for directories that need write access",
		})
	}

	return sr
}

func parseVolume(vol string) (hostPath, containerPath string, readOnly bool) {
	parts := strings.Split(vol, ":")
	switch len(parts) {
	case 1:
		return "", parts[0], false
	case 2:
		if parts[1] == "ro" || parts[1] == "rw" {
			return parts[0], "", parts[1] == "ro"
		}
		return parts[0], parts[1], false
	default:
		readOnly = false
		for _, opt := range parts[2:] {
			if strings.TrimSpace(opt) == "ro" {
				readOnly = true
			}
		}
		return parts[0], parts[1], readOnly
	}
}

func isAbsoluteHostPath(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~")
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Mount Namespace Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:         %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Root FS mounts:         %d\n", r.Summary.RootFSMount)
	fmt.Fprintf(&b, "  Docker socket mounts:   %d\n", r.Summary.DockerSockMount)
	fmt.Fprintf(&b, "  Sensitive mounts:       %d\n", r.Summary.SensitiveMount)
	fmt.Fprintf(&b, "  Writable host mounts:   %d\n", r.Summary.WritableHostMount)
	fmt.Fprintf(&b, "  No read-only root:      %d\n", r.Summary.NoReadOnlyRoot)
	fmt.Fprintf(&b, "  Total findings:         %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.ReadOnly {
			b.WriteString("    Root FS: read-only\n")
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
