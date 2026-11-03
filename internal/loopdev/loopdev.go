package loopdev

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
	LoopDeviceMount   int `json:"loop_device_mount"`
	BlockDeviceMount  int `json:"block_device_mount"`
	CharDeviceAccess  int `json:"char_device_access"`
	FuseMount         int `json:"fuse_mount"`
	DevicePrivileged  int `json:"device_privileged"`
	RawDiskAccess     int `json:"raw_disk_access"`
}

var dangerousDevicePaths = map[string]string{
	"/dev/loop":  "loop device access allows mounting arbitrary filesystem images",
	"/dev/sda":   "raw disk access allows reading/writing host disk directly",
	"/dev/sdb":   "raw disk access allows reading/writing host disk directly",
	"/dev/vda":   "raw virtual disk access allows reading/writing host disk directly",
	"/dev/nvme":  "raw NVMe access allows reading/writing host disk directly",
	"/dev/dm-":   "device-mapper access allows manipulating host LVM/LUKS volumes",
	"/dev/fuse":  "FUSE access allows mounting arbitrary filesystems in container",
	"/dev/nbd":   "network block device access allows attaching remote disks",
	"/dev/kmsg":  "kernel message buffer access can leak sensitive host information",
	"/dev/mem":   "raw memory access allows reading/writing host physical memory",
	"/dev/kmem":  "kernel memory access allows reading/writing kernel address space",
	"/dev/port":  "I/O port access allows direct hardware manipulation",
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

	for _, dev := range svc.Devices {
		lower := strings.ToLower(dev)
		for prefix, reason := range dangerousDevicePaths {
			if strings.Contains(lower, prefix) {
				rule := classifyDeviceRule(prefix)
				sr.Findings = append(sr.Findings, Finding{
					Level:   classifyDeviceLevel(prefix),
					Rule:    rule,
					Message: fmt.Sprintf("Service '%s' accesses device '%s'; %s", svc.Name, dev, reason),
				})
				break
			}
		}
	}

	for _, vol := range svc.Volumes {
		lower := strings.ToLower(vol)
		for prefix, reason := range dangerousDevicePaths {
			if strings.HasPrefix(lower, prefix) || strings.Contains(lower, ":"+prefix) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   classifyDeviceLevel(prefix),
					Rule:    classifyDeviceRule(prefix),
					Message: fmt.Sprintf("Service '%s' mounts device path '%s'; %s", svc.Name, vol, reason),
				})
				break
			}
		}
	}

	if svc.Privileged && len(svc.Devices) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "loopdev_privileged_device",
			Message: fmt.Sprintf("Service '%s' is privileged with explicit device mappings; has unrestricted device access plus specific device exposure", svc.Name),
		})
	}

	if svc.Privileged && hasCapability(svc.CapAdd, "SYS_RAWIO") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "loopdev_rawio_privileged",
			Message: fmt.Sprintf("Service '%s' is privileged with SYS_RAWIO capability; can perform raw I/O on any device", svc.Name),
		})
	}

	if hasCapability(svc.CapAdd, "MKNOD") && !svc.ReadOnly {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "loopdev_mknod_writable",
			Message: fmt.Sprintf("Service '%s' has MKNOD capability on writable filesystem; can create device nodes", svc.Name),
		})
	}

	return sr
}

func classifyDeviceRule(prefix string) string {
	switch {
	case strings.Contains(prefix, "loop"):
		return "loopdev_loop_device"
	case strings.Contains(prefix, "fuse"):
		return "loopdev_fuse_mount"
	case strings.Contains(prefix, "mem") || strings.Contains(prefix, "kmem") || strings.Contains(prefix, "port"):
		return "loopdev_raw_access"
	default:
		return "loopdev_block_device"
	}
}

func classifyDeviceLevel(prefix string) string {
	switch {
	case strings.Contains(prefix, "mem") || strings.Contains(prefix, "kmem") || strings.Contains(prefix, "port"):
		return "critical"
	case strings.Contains(prefix, "loop") || strings.Contains(prefix, "fuse") || strings.Contains(prefix, "nbd"):
		return "high"
	default:
		return "high"
	}
}

func hasCapability(caps []string, target string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, target) || strings.EqualFold(c, "ALL") {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "loopdev_loop_device":
				s.LoopDeviceMount++
			case "loopdev_block_device":
				s.BlockDeviceMount++
			case "loopdev_fuse_mount":
				s.FuseMount++
			case "loopdev_raw_access":
				s.RawDiskAccess++
			case "loopdev_privileged_device":
				s.DevicePrivileged++
			case "loopdev_mknod_writable":
				s.CharDeviceAccess++
			case "loopdev_rawio_privileged":
				s.RawDiskAccess++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Loop Device & Dangerous Device Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Loop device mounts:     %d\n", r.Summary.LoopDeviceMount)
	fmt.Fprintf(&b, "  Block device mounts:    %d\n", r.Summary.BlockDeviceMount)
	fmt.Fprintf(&b, "  Char device access:     %d\n", r.Summary.CharDeviceAccess)
	fmt.Fprintf(&b, "  FUSE mounts:            %d\n", r.Summary.FuseMount)
	fmt.Fprintf(&b, "  Privileged + device:    %d\n", r.Summary.DevicePrivileged)
	fmt.Fprintf(&b, "  Raw disk/memory access: %d\n\n", r.Summary.RawDiskAccess)
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
