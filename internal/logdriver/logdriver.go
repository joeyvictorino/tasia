package logdriver

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
	Driver   string    `json:"driver"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	NoLogging         int `json:"no_logging"`
	NoRotation        int `json:"no_rotation"`
	StealthDrivers    int `json:"stealth_drivers"`
	MissingConfig     int `json:"missing_config"`
	TotalFindings     int `json:"total_findings"`
}

var insecureDrivers = map[string]string{
	"none": "Logging disabled; container activity is invisible to monitoring",
}

var warningDrivers = map[string]string{
	"json-file": "Default json-file driver without rotation can exhaust disk",
	"journald":  "Journald driver may not persist across host reboots without persistent storage",
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
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
		Driver:  "default",
	}

	if svc.Logging == nil {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "log_driver_missing",
			Message: fmt.Sprintf("Service '%s' has no logging configuration; default driver may not persist logs", svc.Name),
		})
		return sr
	}

	lc := svc.Logging
	if lc.Driver != "" {
		sr.Driver = lc.Driver
	}

	if msg, ok := insecureDrivers[lc.Driver]; ok {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "log_driver_stealth",
			Message: fmt.Sprintf("Service '%s' uses driver '%s': %s", svc.Name, lc.Driver, msg),
		})
		return sr
	}

	if msg, ok := warningDrivers[lc.Driver]; ok {
		hasMaxSize := false
		hasMaxFile := false
		if _, ok := lc.Options["max-size"]; ok {
			hasMaxSize = true
		}
		if _, ok := lc.Options["max-file"]; ok {
			hasMaxFile = true
		}

		if !hasMaxSize && !hasMaxFile {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "log_driver_no_rotation",
				Message: fmt.Sprintf("Service '%s' uses '%s' without rotation limits: %s", svc.Name, lc.Driver, msg),
			})
		} else if !hasMaxSize {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "log_driver_no_max_size",
				Message: fmt.Sprintf("Service '%s' uses '%s' without max-size; logs may grow unbounded", svc.Name, lc.Driver),
			})
		}
	}

	if lc.Driver == "syslog" {
		addr := lc.Options["syslog-address"]
		if addr != "" && !strings.HasPrefix(addr, "tcp+tls://") && !strings.HasPrefix(addr, "unix://") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "log_driver_syslog_unencrypted",
				Message: fmt.Sprintf("Service '%s' syslog address %q may transmit logs unencrypted", svc.Name, addr),
			})
		}
	}

	if lc.Driver == "fluentd" || lc.Driver == "gelf" || lc.Driver == "splunk" {
		tag := lc.Options["tag"]
		if tag == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "log_driver_no_tag",
				Message: fmt.Sprintf("Service '%s' uses '%s' without a tag; logs may be hard to correlate", svc.Name, lc.Driver),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "log_driver_missing":
				s.MissingConfig++
			case "log_driver_stealth":
				s.StealthDrivers++
			case "log_driver_no_rotation":
				s.NoRotation++
			case "log_driver_no_max_size":
				s.NoRotation++
			}
		}
		if sr.Driver == "default" {
			s.NoLogging++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Log Driver Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Stealth drivers (none): %d\n", r.Summary.StealthDrivers)
	fmt.Fprintf(&b, "  Missing config:         %d\n", r.Summary.MissingConfig)
	fmt.Fprintf(&b, "  No rotation:            %d\n\n", r.Summary.NoRotation)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s driver: %s\n", sr.Service, sr.Driver)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
