package tmpwatch

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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	TmpWritable       int `json:"tmp_writable"`
	TmpNoTmpfs        int `json:"tmp_no_tmpfs"`
	TmpNoSizeLimit    int `json:"tmp_no_size_limit"`
	TmpHostMounted    int `json:"tmp_host_mounted"`
	TmpSharedVolume   int `json:"tmp_shared_volume"`
	TmpWorldWritable  int `json:"tmp_world_writable"`
}

var tmpPaths = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	sharedVols := findSharedVolumes(c)
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, sharedVols)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func findSharedVolumes(c *collect.Collected) map[string]int {
	counts := map[string]int{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, v := range svc.Volumes {
				parts := strings.SplitN(v, ":", 2)
				if len(parts) == 2 {
					counts[parts[0]]++
				}
			}
		}
	}
	return counts
}

func isTmpPath(path string) bool {
	lower := strings.ToLower(path)
	for _, t := range tmpPaths {
		if lower == t || strings.HasPrefix(lower, t+"/") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string, sharedVols map[string]int) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	hasTmpfs := false
	for _, t := range svc.Tmpfs {
		if isTmpPath(t) {
			hasTmpfs = true
		}
	}

	for _, vol := range svc.Volumes {
		parts := strings.SplitN(vol, ":", 2)
		if len(parts) < 2 {
			continue
		}
		src, dst := parts[0], parts[1]
		dstClean := strings.Split(dst, ":")[0]

		if !isTmpPath(dstClean) {
			continue
		}

		if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "tmpwatch_host_mount",
				Message: fmt.Sprintf("Service '%s' bind-mounts host path '%s' to container '%s'; host temp files may leak into container or vice versa", svc.Name, src, dstClean),
			})
		}

		if sharedVols[src] > 1 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "tmpwatch_shared_vol",
				Message: fmt.Sprintf("Service '%s' shares volume '%s' mounted at '%s' with other services; temp data may leak between containers", svc.Name, src, dstClean),
			})
		}

		if !strings.Contains(vol, ":ro") && !strings.Contains(vol, ":readonly") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "tmpwatch_writable",
				Message: fmt.Sprintf("Service '%s' has writable mount at '%s'; consider read-only or tmpfs for temp paths", svc.Name, dstClean),
			})
		}
	}

	if !svc.ReadOnly && !hasTmpfs {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "tmpwatch_no_tmpfs",
			Message: fmt.Sprintf("Service '%s' has writable rootfs without tmpfs for /tmp; temp files persist on container layer", svc.Name),
		})
	}

	for _, t := range svc.Tmpfs {
		if isTmpPath(t) && !strings.Contains(t, "size=") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "tmpwatch_no_size_limit",
				Message: fmt.Sprintf("Service '%s' has tmpfs at '%s' without size limit; unbounded temp writes could exhaust memory", svc.Name, t),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		s.TotalFindings += len(sr.Findings)
		for _, f := range sr.Findings {
			switch f.Rule {
			case "tmpwatch_writable":
				s.TmpWritable++
			case "tmpwatch_no_tmpfs":
				s.TmpNoTmpfs++
			case "tmpwatch_no_size_limit":
				s.TmpNoSizeLimit++
			case "tmpwatch_host_mount":
				s.TmpHostMounted++
			case "tmpwatch_shared_vol":
				s.TmpSharedVolume++
			case "tmpwatch_world_writable":
				s.TmpWorldWritable++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Temporary File Monitoring Analysis: %s\n", r.Path)
	b.WriteString(strings.Repeat("=", 50) + "\n\n")

	fmt.Fprintf(&b, "  Services:           %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Findings:           %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Tmp writable:       %d\n", r.Summary.TmpWritable)
	fmt.Fprintf(&b, "  Tmp no tmpfs:       %d\n", r.Summary.TmpNoTmpfs)
	fmt.Fprintf(&b, "  Tmp no size limit:  %d\n", r.Summary.TmpNoSizeLimit)
	fmt.Fprintf(&b, "  Tmp host mounted:   %d\n", r.Summary.TmpHostMounted)
	fmt.Fprintf(&b, "  Tmp shared volume:  %d\n", r.Summary.TmpSharedVolume)
	b.WriteString("\n")

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s):\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
