package secretrotation

import (
	"fmt"
	"regexp"
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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	StaticCredential   int `json:"static_credential"`
	EnvSecret          int `json:"env_secret"`
	SharedSecret       int `json:"shared_secret"`
	PrivilegedSecret   int `json:"privileged_secret"`
	HardcodedDefault   int `json:"hardcoded_default"`
	NoRotationLabel    int `json:"no_rotation_label"`
}

var staticCredRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|auth_?key|private_?key|access_?key)`)
var rotationLabelRe = regexp.MustCompile(`(?i)(rotat|renew|expire|ttl|max[._-]?age)`)

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	secretUsage := map[string]int{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, env := range svc.Environment {
				k := strings.SplitN(env, "=", 2)[0]
				if staticCredRe.MatchString(k) {
					secretUsage[k]++
				}
			}
		}
	}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, secretUsage)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, secretUsage map[string]int) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	hasRotationLabel := false
	for k, v := range svc.Labels {
		combined := k + "=" + v
		if rotationLabelRe.MatchString(combined) {
			hasRotationLabel = true
			break
		}
	}

	secretEnvCount := 0
	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		k := parts[0]
		v := ""
		if len(parts) > 1 {
			v = parts[1]
		}

		if !staticCredRe.MatchString(k) {
			continue
		}
		secretEnvCount++

		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "secretrotation_env_secret",
			Message: fmt.Sprintf("Service '%s' passes secret-like variable '%s' via environment; file-mounted secrets are more secure", svc.Name, k),
		})

		if v != "" && !strings.HasPrefix(v, "${") && !strings.HasPrefix(v, "$") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "secretrotation_hardcoded_default",
				Message: fmt.Sprintf("Service '%s' has hardcoded default for secret variable '%s'; rotate credentials and use external secret management", svc.Name, k),
			})
		}

		if secretUsage[k] > 3 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "secretrotation_shared_secret",
				Message: fmt.Sprintf("Service '%s' shares secret variable '%s' with %d other services; increases blast radius if compromised", svc.Name, k, secretUsage[k]),
			})
		}

		if !strings.Contains(strings.ToLower(k), "rotat") && !hasRotationLabel {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "secretrotation_static_credential",
				Message: fmt.Sprintf("Service '%s' uses secret variable '%s' without rotation indicator; static credentials increase exposure window", svc.Name, k),
			})
		}
	}

	if secretEnvCount > 0 && !hasRotationLabel {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "secretrotation_no_rotation_label",
			Message: fmt.Sprintf("Service '%s' uses %d secret variables without rotation labels; add labels to indicate rotation policy", svc.Name, secretEnvCount),
		})
	}

	if svc.Privileged && secretEnvCount > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "secretrotation_privileged_secret",
			Message: fmt.Sprintf("Service '%s' is privileged with %d secret variables; privileged containers can read all secrets from host", svc.Name, secretEnvCount),
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
			case "secretrotation_static_credential":
				s.StaticCredential++
			case "secretrotation_env_secret":
				s.EnvSecret++
			case "secretrotation_shared_secret":
				s.SharedSecret++
			case "secretrotation_privileged_secret":
				s.PrivilegedSecret++
			case "secretrotation_hardcoded_default":
				s.HardcodedDefault++
			case "secretrotation_no_rotation_label":
				s.NoRotationLabel++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Secret Rotation Policy Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Static credentials:     %d\n", r.Summary.StaticCredential)
	fmt.Fprintf(&b, "  Env-passed secrets:     %d\n", r.Summary.EnvSecret)
	fmt.Fprintf(&b, "  Shared secrets (>3):    %d\n", r.Summary.SharedSecret)
	fmt.Fprintf(&b, "  Privileged + secrets:   %d\n", r.Summary.PrivilegedSecret)
	fmt.Fprintf(&b, "  Hardcoded defaults:     %d\n", r.Summary.HardcodedDefault)
	fmt.Fprintf(&b, "  No rotation label:      %d\n\n", r.Summary.NoRotationLabel)
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
