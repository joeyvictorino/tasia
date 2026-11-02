package signals

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name            string    `json:"name"`
	File            string    `json:"file"`
	StopSignal      string    `json:"stop_signal,omitempty"`
	StopGracePeriod string    `json:"stop_grace_period,omitempty"`
	HasInit         bool      `json:"has_init"`
	Findings        []Finding `json:"findings,omitempty"`
	Score           int       `json:"score"`
	Grade           string    `json:"grade"`
}

type Summary struct {
	TotalServices      int `json:"total_services"`
	WithStopSignal     int `json:"with_stop_signal"`
	WithGracePeriod    int `json:"with_grace_period"`
	WithInit           int `json:"with_init"`
	WithSignalIssues   int `json:"with_signal_issues"`
	TotalFindings      int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var validSignals = map[string]bool{
	"SIGTERM": true, "SIGINT": true, "SIGQUIT": true, "SIGKILL": true,
	"SIGHUP": true, "SIGUSR1": true, "SIGUSR2": true, "SIGWINCH": true,
}

var riskySignals = map[string]string{
	"SIGKILL": "SIGKILL prevents graceful shutdown; data may be lost",
	"SIGSTOP": "SIGSTOP cannot be caught; container will freeze without cleanup",
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
		if s.StopSignal != "" {
			summary.WithStopSignal++
		}
		if s.StopGracePeriod != "" {
			summary.WithGracePeriod++
		}
		if s.HasInit {
			summary.WithInit++
		}
		if len(s.Findings) > 0 {
			summary.WithSignalIssues++
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:  svc.Name,
		File:  file,
		Score: 100,
	}

	sr.StopSignal = getStopSignal(svc)
	sr.StopGracePeriod = getStopGracePeriod(svc)
	sr.HasInit = hasInitProcess(svc)

	if sr.StopSignal != "" {
		sig := strings.ToUpper(sr.StopSignal)
		if !strings.HasPrefix(sig, "SIG") {
			sig = "SIG" + sig
		}
		if msg, risky := riskySignals[sig]; risky {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "high",
				Category: "dangerous_stop_signal",
				Detail:   fmt.Sprintf("stop_signal=%s: %s", sr.StopSignal, msg),
			})
			sr.Score -= 25
		} else if !validSignals[sig] {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "low",
				Category: "unusual_stop_signal",
				Detail:   fmt.Sprintf("stop_signal=%s is non-standard; verify application handles it", sr.StopSignal),
			})
			sr.Score -= 5
		}
	}

	if sr.StopGracePeriod != "" {
		secs := parseDurationSeconds(sr.StopGracePeriod)
		if secs > 0 && secs < 5 {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "short_grace_period",
				Detail:   fmt.Sprintf("stop_grace_period=%s is very short; processes may not finish cleanup", sr.StopGracePeriod),
			})
			sr.Score -= 15
		} else if secs > 120 {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "low",
				Category: "long_grace_period",
				Detail:   fmt.Sprintf("stop_grace_period=%s is very long; slow shutdowns may delay deployments", sr.StopGracePeriod),
			})
			sr.Score -= 5
		}
	}

	if !sr.HasInit {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "medium",
			Category: "no_init_process",
			Detail:   "No init process (init: true); zombie processes may accumulate and signals may not propagate",
		})
		sr.Score -= 15
	}

	if svc.Privileged && sr.StopSignal == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "medium",
			Category: "privileged_no_stop_signal",
			Detail:   "Privileged container without explicit stop_signal; default SIGTERM may not reach PID 1",
		})
		sr.Score -= 10
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = scoreToGrade(sr.Score)
	return sr
}

func getStopSignal(svc *compose.Service) string {
	for _, env := range svc.Environment {
		if strings.HasPrefix(env, "STOPSIGNAL=") {
			return strings.TrimPrefix(env, "STOPSIGNAL=")
		}
	}
	for k, v := range svc.Labels {
		if k == "com.docker.compose.stop-signal" {
			return v
		}
	}
	return ""
}

func getStopGracePeriod(svc *compose.Service) string {
	for _, env := range svc.Environment {
		if strings.HasPrefix(env, "STOP_GRACE_PERIOD=") {
			return strings.TrimPrefix(env, "STOP_GRACE_PERIOD=")
		}
	}
	for k, v := range svc.Labels {
		if k == "com.docker.compose.stop-grace-period" {
			return v
		}
	}
	return ""
}

func hasInitProcess(svc *compose.Service) bool {
	for _, env := range svc.Environment {
		if env == "TINI_SUBREAPER=1" || env == "TINI_KILL_PROCESS_GROUP=1" {
			return true
		}
	}
	img := strings.ToLower(svc.Image)
	if strings.Contains(img, "tini") || strings.Contains(img, "dumb-init") {
		return true
	}
	for k, v := range svc.Labels {
		if k == "com.docker.compose.init" && (v == "true" || v == "1") {
			return true
		}
	}
	return false
}

func parseDurationSeconds(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "ms") {
		numStr := strings.TrimSuffix(s, "ms")
		if v, err := strconv.Atoi(numStr); err == nil {
			return v / 1000
		}
	}
	if strings.HasSuffix(s, "s") {
		numStr := strings.TrimSuffix(s, "s")
		if v, err := strconv.Atoi(numStr); err == nil {
			return v
		}
	}
	if strings.HasSuffix(s, "m") {
		numStr := strings.TrimSuffix(s, "m")
		if v, err := strconv.Atoi(numStr); err == nil {
			return v * 60
		}
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return 0
}

func scoreToGrade(score int) string {
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
	var b strings.Builder
	fmt.Fprintf(&b, "Signal Handling Audit (%d services, %d with issues, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.WithSignalIssues, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  With stop_signal:      %d\n", r.Summary.WithStopSignal)
	fmt.Fprintf(&b, "  With grace period:     %d\n", r.Summary.WithGracePeriod)
	fmt.Fprintf(&b, "  With init process:     %d\n\n", r.Summary.WithInit)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-30s [%s] score=%d\n", s.Name, s.Grade, s.Score)
		if s.StopSignal != "" {
			fmt.Fprintf(&b, "    stop_signal: %s\n", s.StopSignal)
		}
		if s.StopGracePeriod != "" {
			fmt.Fprintf(&b, "    stop_grace_period: %s\n", s.StopGracePeriod)
		}
		if s.HasInit {
			fmt.Fprintf(&b, "    init: true\n")
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Category, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
