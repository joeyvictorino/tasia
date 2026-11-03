package coredump

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
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	UnlimitedCore    int `json:"unlimited_core"`
	SuidDumpable     int `json:"suid_dumpable"`
	CorePathMount    int `json:"core_path_mount"`
	CoreEnvExposed   int `json:"core_env_exposed"`
	CorePrivileged   int `json:"core_privileged"`
	CoreNoSeccomp    int `json:"core_no_seccomp"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if ul, ok := svc.Ulimits["core"]; ok && (ul.Soft == -1 || ul.Hard == -1) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "coredump_unlimited",
			Message: fmt.Sprintf("Service '%s' has unlimited core dump size (ulimit core soft=%d hard=%d); core dumps may contain secrets, credentials, or encryption keys", svc.Name, ul.Soft, ul.Hard),
		})
	}

	if val, ok := svc.Sysctls["fs.suid_dumpable"]; ok && (val == "1" || val == "2") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "coredump_suid_dumpable",
			Message: fmt.Sprintf("Service '%s' has fs.suid_dumpable=%s; setuid programs will produce core dumps that may leak privileged memory", svc.Name, val),
		})
	}

	for _, vol := range svc.Volumes {
		parts := strings.SplitN(vol, ":", 2)
		if len(parts) == 2 {
			dest := parts[1]
			if strings.Contains(dest, "core") || strings.HasPrefix(dest, "/var/crash") || strings.HasPrefix(dest, "/var/lib/systemd/coredump") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "coredump_path_mount",
					Message: fmt.Sprintf("Service '%s' mounts a core dump path (%s); dumps on host storage may persist sensitive data", svc.Name, vol),
				})
				break
			}
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := strings.ToUpper(parts[0])
			if (strings.Contains(key, "CORE") && strings.Contains(key, "DUMP")) || key == "CORE_PATTERN" {
				if !strings.HasPrefix(parts[1], "${") {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "low",
						Rule:    "coredump_env_exposed",
						Message: fmt.Sprintf("Service '%s' exposes core dump configuration via environment variable '%s'", svc.Name, parts[0]),
					})
					break
				}
			}
		}
	}

	hasUnlimitedCore := false
	if ul, ok := svc.Ulimits["core"]; ok && (ul.Soft == -1 || ul.Hard == -1) {
		hasUnlimitedCore = true
	}

	if svc.Privileged && hasUnlimitedCore {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "coredump_privileged",
			Message: fmt.Sprintf("Service '%s' is privileged with unlimited core dumps; a crash can dump host kernel memory and secrets to disk", svc.Name),
		})
	}

	hasSeccomp := false
	for _, opt := range svc.SecurityOpt {
		if strings.Contains(opt, "seccomp") && !strings.Contains(opt, "unconfined") {
			hasSeccomp = true
			break
		}
	}
	if hasUnlimitedCore && !hasSeccomp {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "coredump_no_seccomp",
			Message: fmt.Sprintf("Service '%s' allows unlimited core dumps without a seccomp profile; no syscall filter protects against forced dumps", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "coredump_unlimited":
				s.UnlimitedCore++
			case "coredump_suid_dumpable":
				s.SuidDumpable++
			case "coredump_path_mount":
				s.CorePathMount++
			case "coredump_env_exposed":
				s.CoreEnvExposed++
			case "coredump_privileged":
				s.CorePrivileged++
			case "coredump_no_seccomp":
				s.CoreNoSeccomp++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Core Dump Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unlimited core dumps:  %d\n", r.Summary.UnlimitedCore)
	fmt.Fprintf(&b, "  SUID dumpable:         %d\n", r.Summary.SuidDumpable)
	fmt.Fprintf(&b, "  Core path mounts:      %d\n", r.Summary.CorePathMount)
	fmt.Fprintf(&b, "  Core env exposed:      %d\n", r.Summary.CoreEnvExposed)
	fmt.Fprintf(&b, "  Privileged + coredump: %d\n", r.Summary.CorePrivileged)
	fmt.Fprintf(&b, "  No seccomp profile:    %d\n\n", r.Summary.CoreNoSeccomp)
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
