package graceful

import (
	"fmt"
	"strconv"
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
	Service         string    `json:"service"`
	File            string    `json:"file"`
	StopSignal      string    `json:"stop_signal"`
	StopGracePeriod string    `json:"stop_grace_period"`
	Findings        []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	NoStopSignal    int `json:"no_stop_signal"`
	HardKillSignal  int `json:"hard_kill_signal"`
	ShortGrace      int `json:"short_grace"`
	LongGrace       int `json:"long_grace"`
	TotalFindings   int `json:"total_findings"`
}

var hardKillSignals = []string{"SIGKILL", "KILL", "9"}

func isHardKill(signal string) bool {
	upper := strings.ToUpper(strings.TrimSpace(signal))
	for _, s := range hardKillSignals {
		if upper == s {
			return true
		}
	}
	return false
}

func parseGracePeriodSeconds(period string) (int, bool) {
	period = strings.TrimSpace(period)
	if period == "" {
		return 0, false
	}
	if strings.HasSuffix(period, "s") {
		val := strings.TrimSuffix(period, "s")
		n, err := strconv.Atoi(val)
		if err == nil {
			return n, true
		}
	}
	if strings.HasSuffix(period, "m") {
		val := strings.TrimSuffix(period, "m")
		n, err := strconv.Atoi(val)
		if err == nil {
			return n * 60, true
		}
	}
	n, err := strconv.Atoi(period)
	if err == nil {
		return n, true
	}
	return 0, false
}

func isStatefulService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image + " " + svc.Name)
	indicators := []string{
		"postgres", "mysql", "mariadb", "redis", "mongodb", "mongo",
		"elasticsearch", "kafka", "rabbitmq", "milvus", "chromadb",
		"weaviate", "qdrant", "etcd", "consul", "vault",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
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
		Service:         svc.Name,
		File:            file,
		StopSignal:      svc.StopSignal,
		StopGracePeriod: svc.StopGracePeriod,
	}

	if isHardKill(svc.StopSignal) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "graceful_hard_kill",
			Message: fmt.Sprintf("Service '%s' uses %s as stop signal; data loss risk on shutdown", svc.Name, svc.StopSignal),
		})
	}

	if svc.StopSignal == "" && isStatefulService(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "graceful_no_signal",
			Message: fmt.Sprintf("Stateful service '%s' has no explicit stop_signal; relies on default SIGTERM", svc.Name),
		})
	}

	if secs, ok := parseGracePeriodSeconds(svc.StopGracePeriod); ok {
		if secs < 5 && isStatefulService(svc) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "graceful_short_period",
				Message: fmt.Sprintf("Stateful service '%s' has stop_grace_period of %ds; may not flush data before kill", svc.Name, secs),
			})
		}
		if secs > 300 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "info",
				Rule:    "graceful_long_period",
				Message: fmt.Sprintf("Service '%s' has stop_grace_period of %ds; long waits delay orchestrator operations", svc.Name, secs),
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
			case "graceful_no_signal":
				s.NoStopSignal++
			case "graceful_hard_kill":
				s.HardKillSignal++
			case "graceful_short_period":
				s.ShortGrace++
			case "graceful_long_period":
				s.LongGrace++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Graceful Shutdown Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No stop signal:    %d\n", r.Summary.NoStopSignal)
	fmt.Fprintf(&b, "  Hard kill signal:  %d\n", r.Summary.HardKillSignal)
	fmt.Fprintf(&b, "  Short grace:       %d\n", r.Summary.ShortGrace)
	fmt.Fprintf(&b, "  Long grace:        %d\n\n", r.Summary.LongGrace)
	for _, sr := range r.Services {
		sig := sr.StopSignal
		if sig == "" {
			sig = "(default)"
		}
		grace := sr.StopGracePeriod
		if grace == "" {
			grace = "(default)"
		}
		fmt.Fprintf(&b, "  %-30s signal: %s  grace: %s\n", sr.Service, sig, grace)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
