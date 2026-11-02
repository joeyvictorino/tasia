package blkio

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
	Weight   int       `json:"weight"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	WithWeight      int `json:"with_weight"`
	WithDeviceLimits int `json:"with_device_limits"`
	TotalFindings   int `json:"total_findings"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	var allWeights []weightInfo
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
			if svc.BlkioWeight > 0 {
				allWeights = append(allWeights, weightInfo{name: svc.Name, weight: svc.BlkioWeight})
			}
		}
	}
	unbalanced := detectUnbalanced(allWeights)
	for i := range r.Services {
		for _, uf := range unbalanced {
			if uf.service == r.Services[i].Service {
				r.Services[i].Findings = append(r.Services[i].Findings, uf.finding)
			}
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

type weightInfo struct {
	name   string
	weight int
}

type unbalancedFinding struct {
	service string
	finding Finding
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
		Weight:  svc.BlkioWeight,
	}

	hasBlkio := svc.BlkioWeight > 0 || len(svc.BlkioWeightDevice) > 0 ||
		len(svc.BlkioDeviceReadBps) > 0 || len(svc.BlkioDeviceWriteBps) > 0 ||
		len(svc.BlkioDeviceReadIOps) > 0 || len(svc.BlkioDeviceWriteIOps) > 0

	if !hasBlkio {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "blkio_weight_missing",
			Message: fmt.Sprintf("Service '%s' has no blkio_config.weight set; I/O priority is uncontrolled", svc.Name),
		})
	}

	if svc.BlkioWeight == 10 || svc.BlkioWeight == 1000 {
		label := "starve other containers"
		if svc.BlkioWeight == 10 {
			label = "be starved under I/O contention"
		}
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "blkio_weight_extreme",
			Message: fmt.Sprintf("Service '%s' has blkio weight %d (extreme); may %s", svc.Name, svc.BlkioWeight, label),
		})
	}

	hasDeviceLimits := len(svc.BlkioDeviceReadBps) > 0 || len(svc.BlkioDeviceWriteBps) > 0 ||
		len(svc.BlkioDeviceReadIOps) > 0 || len(svc.BlkioDeviceWriteIOps) > 0
	if hasBlkio && !hasDeviceLimits {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "blkio_no_device_limits",
			Message: fmt.Sprintf("Service '%s' has blkio weight but no per-device read/write rate limits", svc.Name),
		})
	}

	hasBpsLimits := len(svc.BlkioDeviceReadBps) > 0 || len(svc.BlkioDeviceWriteBps) > 0
	hasIopsLimits := len(svc.BlkioDeviceReadIOps) > 0 || len(svc.BlkioDeviceWriteIOps) > 0
	if hasBpsLimits && !hasIopsLimits {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "blkio_no_iops_limit",
			Message: fmt.Sprintf("Service '%s' has byte-rate limits but no IOPS limits; small random I/O is unbounded", svc.Name),
		})
	}

	devices := collectDevicePaths(svc)
	for _, d := range devices {
		if !isStandardBlockDevice(d) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "blkio_rate_limit_missing_device",
				Message: fmt.Sprintf("Service '%s' references non-standard device path '%s'; verify it exists on target host", svc.Name, d),
			})
		}
	}

	return sr
}

func collectDevicePaths(svc compose.Service) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, lists := range [][]compose.BlkioRateDevice{
		svc.BlkioDeviceReadBps, svc.BlkioDeviceWriteBps,
		svc.BlkioDeviceReadIOps, svc.BlkioDeviceWriteIOps,
	} {
		for _, d := range lists {
			if !seen[d.Path] {
				seen[d.Path] = true
				paths = append(paths, d.Path)
			}
		}
	}
	for _, wd := range svc.BlkioWeightDevice {
		if !seen[wd.Path] {
			seen[wd.Path] = true
			paths = append(paths, wd.Path)
		}
	}
	return paths
}

func isStandardBlockDevice(path string) bool {
	return strings.HasPrefix(path, "/dev/sd") ||
		strings.HasPrefix(path, "/dev/vd") ||
		strings.HasPrefix(path, "/dev/xvd") ||
		strings.HasPrefix(path, "/dev/nvme") ||
		strings.HasPrefix(path, "/dev/hd") ||
		strings.HasPrefix(path, "/dev/loop")
}

func detectUnbalanced(weights []weightInfo) []unbalancedFinding {
	var findings []unbalancedFinding
	for i := 0; i < len(weights); i++ {
		for j := i + 1; j < len(weights); j++ {
			ratio := float64(weights[i].weight) / float64(weights[j].weight)
			if ratio < 1 {
				ratio = 1 / ratio
			}
			if ratio > 10 {
				msg := fmt.Sprintf("Services '%s' (weight %d) and '%s' (weight %d) have >10x I/O weight disparity",
					weights[i].name, weights[i].weight, weights[j].name, weights[j].weight)
				findings = append(findings, unbalancedFinding{
					service: weights[i].name,
					finding: Finding{Level: "high", Rule: "blkio_unbalanced_weights", Message: msg},
				})
				findings = append(findings, unbalancedFinding{
					service: weights[j].name,
					finding: Finding{Level: "high", Rule: "blkio_unbalanced_weights", Message: msg},
				})
			}
		}
	}
	return findings
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if sr.Weight > 0 {
			s.WithWeight++
		}
		s.TotalFindings += len(sr.Findings)
	}
	for _, sr := range services {
		for _, f := range sr.Findings {
			if f.Rule != "blkio_no_device_limits" && f.Rule != "blkio_weight_missing" {
				continue
			}
		}
		_ = sr
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Block I/O Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Services with weight: %d\n\n", r.Summary.WithWeight)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s weight: %d\n", sr.Service, sr.Weight)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
