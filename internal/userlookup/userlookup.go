package userlookup

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
	MissingUser         int `json:"missing_user"`
	RootUsers           int `json:"root_users"`
	NumericOnly         int `json:"numeric_only"`
	MismatchedGroups    int `json:"mismatched_groups"`
	HighPrivilegeUsers  int `json:"high_privilege_users"`
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

	if svc.User == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "userlookup_missing_user",
			Message: fmt.Sprintf("Service '%s' has no 'user:' directive; container will run as the image default (often root)", svc.Name),
		})
	}

	if isRoot(svc.User) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "userlookup_root_user",
			Message: fmt.Sprintf("Service '%s' explicitly runs as root (user: '%s')", svc.Name, svc.User),
		})
	}

	if svc.User != "" && isNumericOnly(svc.User) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "userlookup_numeric_uid",
			Message: fmt.Sprintf("Service '%s' uses numeric-only UID '%s' without a mapped user name; harder to audit", svc.Name, svc.User),
		})
	}

	if svc.User != "" && svc.GroupName != "" {
		userPart := strings.SplitN(svc.User, ":", 2)[0]
		if isHighPrivilege(userPart) && !isHighPrivilege(svc.GroupName) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "userlookup_mismatched_group",
				Message: fmt.Sprintf("Service '%s' has user '%s' with group '%s'; user/group privilege level mismatch", svc.Name, userPart, svc.GroupName),
			})
		}
	}

	if svc.User != "" && !isRoot(svc.User) && isHighPrivilege(svc.User) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "userlookup_high_privilege",
			Message: fmt.Sprintf("Service '%s' runs as high-privilege user '%s'", svc.Name, svc.User),
		})
	}

	return sr
}

func isRoot(user string) bool {
	u := strings.SplitN(user, ":", 2)[0]
	return u == "root" || u == "0"
}

func isNumericOnly(user string) bool {
	u := strings.SplitN(user, ":", 2)[0]
	_, err := strconv.Atoi(u)
	return err == nil
}

func isHighPrivilege(name string) bool {
	n := strings.SplitN(name, ":", 2)[0]
	switch n {
	case "root", "0", "daemon", "bin", "sys", "adm", "wheel", "sudo":
		return true
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "userlookup_missing_user":
				s.MissingUser++
			case "userlookup_root_user":
				s.RootUsers++
			case "userlookup_numeric_uid":
				s.NumericOnly++
			case "userlookup_mismatched_group":
				s.MismatchedGroups++
			case "userlookup_high_privilege":
				s.HighPrivilegeUsers++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "User Identity Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing user directive:   %d\n", r.Summary.MissingUser)
	fmt.Fprintf(&b, "  Root users:               %d\n", r.Summary.RootUsers)
	fmt.Fprintf(&b, "  Numeric-only UIDs:        %d\n", r.Summary.NumericOnly)
	fmt.Fprintf(&b, "  Mismatched groups:        %d\n", r.Summary.MismatchedGroups)
	fmt.Fprintf(&b, "  High-privilege users:     %d\n\n", r.Summary.HighPrivilegeUsers)
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
