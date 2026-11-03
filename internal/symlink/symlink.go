package symlink

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
	TotalServices          int `json:"total_services"`
	TotalFindings          int `json:"total_findings"`
	SymlinkTraversalRisks  int `json:"symlink_traversal_risks"`
	WritableSymlinkTargets int `json:"writable_symlink_targets"`
	RootFSSymlinkRisks     int `json:"rootfs_symlink_risks"`
	MissingReadOnly        int `json:"missing_read_only"`
}

var sensitivePaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts",
	"/etc/resolv.conf", "/etc/hostname",
	"/proc", "/sys", "/dev",
	"/var/run/docker.sock", "/run/docker.sock",
	"/root", "/home",
}

var symlinkVulnerablePaths = []string{
	"/tmp", "/var/tmp", "/dev/shm",
	"/var/log", "/var/cache",
	"/run", "/var/run",
}

func isSensitivePath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, s := range sensitivePaths {
		if path == s || strings.HasPrefix(path, s+"/") {
			return true
		}
	}
	return false
}

func isSymlinkVulnerablePath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, s := range symlinkVulnerablePaths {
		if path == s || strings.HasPrefix(path, s+"/") {
			return true
		}
	}
	return false
}

func isWritableMount(volumeSpec string) bool {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) < 3 {
		return true
	}
	opts := strings.ToLower(parts[2])
	return !strings.Contains(opts, "ro")
}

func containerPath(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) >= 2 {
		return parts[1]
	}
	return parts[0]
}

func hostPath(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	return parts[0]
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, v := range svc.Volumes {
		hp := hostPath(v)
		cp := containerPath(v)
		writable := isWritableMount(v)

		if isSymlinkVulnerablePath(cp) && writable {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "symlink_traversal_risk",
				Message: fmt.Sprintf("Service '%s' mounts writable path '%s' at symlink-vulnerable location '%s'; an attacker can plant symlinks to escape the mount boundary", svc.Name, hp, cp),
			})
		}

		if isSensitivePath(cp) && writable {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "writable_sensitive_target",
				Message: fmt.Sprintf("Service '%s' mounts '%s' writable at sensitive path '%s'; symlink attacks could modify host system files", svc.Name, hp, cp),
			})
		}

		if cp == "/" && writable {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "rootfs_symlink_risk",
				Message: fmt.Sprintf("Service '%s' mounts '%s' at container root '/'; symlinks anywhere in the filesystem can traverse to the host", svc.Name, hp),
			})
		}

		if isSymlinkVulnerablePath(hp) && writable {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "host_symlink_source",
				Message: fmt.Sprintf("Service '%s' bind-mounts host symlink-vulnerable path '%s'; host-side symlinks could expose unintended content inside the container", svc.Name, hp),
			})
		}
	}

	hasTmpMount := false
	for _, v := range svc.Volumes {
		cp := containerPath(v)
		if isSymlinkVulnerablePath(cp) {
			hasTmpMount = true
			if isWritableMount(v) {
				parts := strings.Split(v, ":")
				if len(parts) < 3 || !strings.Contains(strings.ToLower(parts[2]), "ro") {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "medium",
						Rule:    "missing_nosuid_noexec",
						Message: fmt.Sprintf("Service '%s' mounts '%s' writable without nosuid/noexec options; symlink payloads could include setuid binaries", svc.Name, cp),
					})
				}
			}
		}
	}

	if len(svc.Volumes) > 0 && !hasTmpMount {
		hasWritable := false
		for _, v := range svc.Volumes {
			if isWritableMount(v) {
				hasWritable = true
				break
			}
		}
		if hasWritable {
			readOnlyRoot := false
			for _, sc := range svc.SecurityOpt {
				if strings.Contains(strings.ToLower(sc), "read-only") {
					readOnlyRoot = true
				}
			}
			if svc.ReadOnly {
				readOnlyRoot = true
			}
			if !readOnlyRoot {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "missing_read_only_root",
					Message: fmt.Sprintf("Service '%s' has writable mounts but no read-only root filesystem; consider read_only: true to limit symlink attack surface", svc.Name),
				})
			}
		}
	}

	return sr
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "symlink_traversal_risk", "host_symlink_source":
				s.SymlinkTraversalRisks++
			case "writable_sensitive_target", "missing_nosuid_noexec":
				s.WritableSymlinkTargets++
			case "rootfs_symlink_risk":
				s.RootFSSymlinkRisks++
			case "missing_read_only_root":
				s.MissingReadOnly++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Symlink Traversal Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Symlink traversal risks:   %d\n", r.Summary.SymlinkTraversalRisks)
	fmt.Fprintf(&b, "  Writable symlink targets:  %d\n", r.Summary.WritableSymlinkTargets)
	fmt.Fprintf(&b, "  Root FS symlink risks:     %d\n", r.Summary.RootFSSymlinkRisks)
	fmt.Fprintf(&b, "  Missing read-only root:    %d\n\n", r.Summary.MissingReadOnly)
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
