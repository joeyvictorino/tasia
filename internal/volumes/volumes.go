package volumes

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type MountFinding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Volume   string `json:"volume"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type MountInfo struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	Type     string `json:"type"`
}

type Report struct {
	Path     string         `json:"path"`
	Mounts   []MountInfo    `json:"mounts"`
	Findings []MountFinding `json:"findings"`
	Summary  Summary        `json:"summary"`
}

type Summary struct {
	TotalMounts    int `json:"total_mounts"`
	HostBindMounts int `json:"host_bind_mounts"`
	NamedVolumes   int `json:"named_volumes"`
	AnonymousMounts int `json:"anonymous_mounts"`
	ReadOnlyMounts int `json:"read_only_mounts"`
	WritableMounts int `json:"writable_mounts"`
	Findings       int `json:"findings"`
}

var sensitivePaths = map[string]string{
	"/var/run/docker.sock": "Docker socket mount enables container escape",
	"/proc":                "Host /proc mount exposes kernel and process information",
	"/sys":                 "Host /sys mount exposes kernel subsystem controls",
	"/dev":                 "Host /dev mount exposes hardware devices",
	"/etc/shadow":          "Mount exposes password hashes",
	"/etc/passwd":          "Mount exposes user account information",
	"/etc/sudoers":         "Mount exposes sudo configuration",
	"/root":                "Mount exposes root home directory",
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			analyzeMounts(svc, cf.Path, &r)
		}
	}
	r.Summary = summarize(r.Mounts, r.Findings)
	return r
}

func analyzeMounts(svc compose.Service, file string, r *Report) {
	for _, v := range svc.Volumes {
		mi := parseMountSpec(v, svc.Name, file)
		r.Mounts = append(r.Mounts, mi)

		for sp, detail := range sensitivePaths {
			if mi.Source == sp || strings.HasPrefix(mi.Source, sp+"/") {
				severity := "high"
				if mi.Source == "/var/run/docker.sock" {
					severity = "critical"
				}
				r.Findings = append(r.Findings, MountFinding{
					Service:  svc.Name,
					File:     file,
					Volume:   v,
					Category: "sensitive_mount",
					Severity: severity,
					Detail:   detail,
				})
			}
		}

		if mi.Type == "bind" && !mi.ReadOnly {
			if isHostSystemPath(mi.Source) {
				r.Findings = append(r.Findings, MountFinding{
					Service:  svc.Name,
					File:     file,
					Volume:   v,
					Category: "writable_host_mount",
					Severity: "medium",
					Detail:   fmt.Sprintf("Writable bind mount to host path %s; consider :ro if write access is not needed", mi.Source),
				})
			}
		}

		if mi.Type == "anonymous" {
			r.Findings = append(r.Findings, MountFinding{
				Service:  svc.Name,
				File:     file,
				Volume:   v,
				Category: "anonymous_volume",
				Severity: "low",
				Detail:   "Anonymous volume; data is lost on container removal. Use a named volume for persistence",
			})
		}
	}
}

func parseMountSpec(spec, service, file string) MountInfo {
	mi := MountInfo{
		Service: service,
		File:    file,
	}

	parts := strings.SplitN(spec, ":", 3)
	switch {
	case len(parts) == 1:
		mi.Target = parts[0]
		if strings.HasPrefix(parts[0], "/") || strings.HasPrefix(parts[0], ".") {
			mi.Type = "anonymous"
		} else {
			mi.Type = "named"
			mi.Source = parts[0]
		}
	case len(parts) >= 2:
		mi.Source = parts[0]
		mi.Target = parts[1]
		if len(parts) == 3 && strings.Contains(parts[2], "ro") {
			mi.ReadOnly = true
		}
		if strings.HasPrefix(mi.Source, "/") || strings.HasPrefix(mi.Source, ".") || strings.HasPrefix(mi.Source, "~") {
			mi.Type = "bind"
		} else {
			mi.Type = "named"
		}
	}
	return mi
}

func isHostSystemPath(path string) bool {
	systemPrefixes := []string{"/etc", "/var", "/usr", "/opt", "/root", "/home"}
	for _, p := range systemPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func summarize(mounts []MountInfo, findings []MountFinding) Summary {
	s := Summary{
		TotalMounts: len(mounts),
		Findings:    len(findings),
	}
	for _, m := range mounts {
		switch m.Type {
		case "bind":
			s.HostBindMounts++
		case "named":
			s.NamedVolumes++
		case "anonymous":
			s.AnonymousMounts++
		}
		if m.ReadOnly {
			s.ReadOnlyMounts++
		} else {
			s.WritableMounts++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Volume Mount Audit (%d mounts, %d findings)\n\n",
		r.Summary.TotalMounts, r.Summary.Findings)

	fmt.Fprintf(&b, "  Bind mounts: %d  Named: %d  Anonymous: %d\n",
		r.Summary.HostBindMounts, r.Summary.NamedVolumes, r.Summary.AnonymousMounts)
	fmt.Fprintf(&b, "  Read-only: %d  Writable: %d\n\n",
		r.Summary.ReadOnlyMounts, r.Summary.WritableMounts)

	if len(r.Findings) > 0 {
		fmt.Fprintln(&b, "  Findings:")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "    [%s] %s in %s (%s)\n", f.Severity, f.Service, f.File, f.Category)
			fmt.Fprintf(&b, "      volume: %s\n", f.Volume)
			fmt.Fprintf(&b, "      %s\n\n", f.Detail)
		}
	}

	if len(r.Mounts) > 0 {
		fmt.Fprintln(&b, "  All Mounts:")
		for _, m := range r.Mounts {
			ro := "rw"
			if m.ReadOnly {
				ro = "ro"
			}
			fmt.Fprintf(&b, "    %-20s %-8s %-30s -> %-30s [%s]\n",
				m.Service, m.Type, m.Source, m.Target, ro)
		}
	}
	return b.String()
}
