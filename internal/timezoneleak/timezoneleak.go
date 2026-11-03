package timezoneleak

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	TzEnvSet            int `json:"tz_env_set"`
	LocaleEnvSet        int `json:"locale_env_set"`
	TimezoneMount       int `json:"timezone_mount"`
	TzLabelExposed      int `json:"tz_label_exposed"`
	InconsistentTz      int `json:"inconsistent_tz"`
	TzMountHostNetwork  int `json:"tz_mount_host_network"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	tzValues := map[string]bool{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, env := range svc.Environment {
				parts := strings.SplitN(env, "=", 2)
				if strings.ToUpper(parts[0]) == "TZ" && len(parts) > 1 && parts[1] != "" {
					tzValues[parts[1]] = true
				}
			}
		}
	}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, len(tzValues) > 1)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, multiTz bool) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	hasTzMount := false
	for _, vol := range svc.Volumes {
		lower := strings.ToLower(vol)
		if strings.Contains(lower, "/etc/localtime") || strings.Contains(lower, "/etc/timezone") {
			hasTzMount = true
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "timezoneleak_timezone_mount",
				Message: fmt.Sprintf("Service '%s' mounts host timezone path '%s'; leaks host timezone information", svc.Name, vol),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		k := strings.ToUpper(parts[0])
		v := ""
		if len(parts) > 1 {
			v = parts[1]
		}

		if k == "TZ" && v != "" && v != "UTC" && v != "Etc/UTC" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "timezoneleak_tz_env_set",
				Message: fmt.Sprintf("Service '%s' sets TZ=%s; timezone fingerprints geographic location", svc.Name, v),
			})
		}

		if (k == "LANG" || k == "LC_ALL" || k == "LC_CTYPE" || k == "LANGUAGE") && v != "" && v != "C" && v != "POSIX" && v != "C.UTF-8" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "timezoneleak_locale_env_set",
				Message: fmt.Sprintf("Service '%s' sets %s=%s; locale settings can fingerprint deployment region", svc.Name, k, v),
			})
		}
	}

	for k, v := range svc.Labels {
		combined := strings.ToLower(k + "=" + v)
		if strings.Contains(combined, "timezone") || strings.Contains(combined, "tz=") || strings.Contains(combined, "locale") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "timezoneleak_tz_label_exposed",
				Message: fmt.Sprintf("Service '%s' exposes timezone/locale via label '%s=%s'", svc.Name, k, v),
			})
		}
	}

	if multiTz {
		for _, env := range svc.Environment {
			parts := strings.SplitN(env, "=", 2)
			if strings.ToUpper(parts[0]) == "TZ" && len(parts) > 1 && parts[1] != "" {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "timezoneleak_inconsistent_tz",
					Message: fmt.Sprintf("Service '%s' uses TZ=%s but other services use different timezones; inconsistency may cause log correlation issues", svc.Name, parts[1]),
				})
				break
			}
		}
	}

	if hasTzMount && svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "timezoneleak_tz_mount_host_network",
			Message: fmt.Sprintf("Service '%s' mounts timezone from host with host network; timezone combined with network metadata enables geolocation correlation", svc.Name),
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
			case "timezoneleak_tz_env_set":
				s.TzEnvSet++
			case "timezoneleak_locale_env_set":
				s.LocaleEnvSet++
			case "timezoneleak_timezone_mount":
				s.TimezoneMount++
			case "timezoneleak_tz_label_exposed":
				s.TzLabelExposed++
			case "timezoneleak_inconsistent_tz":
				s.InconsistentTz++
			case "timezoneleak_tz_mount_host_network":
				s.TzMountHostNetwork++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Timezone/Locale Leak Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  TZ env set:             %d\n", r.Summary.TzEnvSet)
	fmt.Fprintf(&b, "  Locale env set:         %d\n", r.Summary.LocaleEnvSet)
	fmt.Fprintf(&b, "  Timezone mount:         %d\n", r.Summary.TimezoneMount)
	fmt.Fprintf(&b, "  TZ label exposed:       %d\n", r.Summary.TzLabelExposed)
	fmt.Fprintf(&b, "  Inconsistent TZ:        %d\n", r.Summary.InconsistentTz)
	fmt.Fprintf(&b, "  TZ mount + host net:    %d\n\n", r.Summary.TzMountHostNetwork)
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
