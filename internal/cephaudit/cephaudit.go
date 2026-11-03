package cephaudit

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
	Findings []Finding `json:"findings"`
}

type Summary struct {
	NoAuth           int `json:"no_auth"`
	PartialAuth      int `json:"partial_auth"`
	NoEncryption     int `json:"no_encryption"`
	ExposedPort      int `json:"exposed_port"`
	DefaultPassword  int `json:"default_password"`
	DemoMode         int `json:"demo_mode"`
	DebugEnabled     int `json:"debug_enabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var cephImages = []string{
	"ceph/ceph", "ceph/daemon", "ceph/demo",
	"quay.io/ceph/ceph", "rook/ceph",
	"digitalocean/ceph", "ceph/radosgw",
}

func isCephImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range cephImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ceph_auth=none") ||
			strings.Contains(lower, "auth_cluster_required=none") ||
			strings.Contains(lower, "auth_service_required=none") ||
			strings.Contains(lower, "auth_client_required=none") {
			return false
		}
		if strings.Contains(lower, "cephx") || strings.Contains(lower, "ceph_auth=cephx") {
			return true
		}
	}
	return true
}

func hasPartialAuth(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "auth_cluster_required=none") ||
			strings.Contains(lower, "auth_service_required=none") ||
			strings.Contains(lower, "auth_client_required=none") {
			return true
		}
	}
	return false
}

func hasNoEncryption(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ms_encrypt=false") ||
			strings.Contains(lower, "ms_cluster_encrypt=false") ||
			strings.Contains(lower, "ms_service_encrypt=false") ||
			strings.Contains(lower, "ms_client_encrypt=false") {
			return true
		}
	}
	return false
}

func hasDefaultDashboardPassword(envs []string) bool {
	defaults := []string{"admin", "ceph", "password", "changeme", "default"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "dashboard") && strings.Contains(lower, "password=") {
			for _, d := range defaults {
				if strings.Contains(lower, "password="+d) {
					return true
				}
			}
		}
	}
	return false
}

func isDemoMode(envs []string, image string) bool {
	if strings.Contains(strings.ToLower(image), "ceph/demo") {
		return true
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "demo") && strings.Contains(lower, "mode") {
			return true
		}
	}
	return false
}

func hasDebugEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "debug_") || (strings.Contains(lower, "debug") && strings.Contains(lower, "=true")) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ceph_no_auth",
			Message: fmt.Sprintf("service %q: Ceph authentication disabled (cephx off)", svc.Name),
		})
	}

	if hasPartialAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "ceph_partial_auth",
			Message: fmt.Sprintf("service %q: Ceph has partial auth — some auth domains set to none", svc.Name),
		})
	}

	if hasNoEncryption(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "ceph_no_encryption",
			Message: fmt.Sprintf("service %q: Ceph messenger encryption disabled", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		6789: "Ceph monitor (legacy v1)",
		3300: "Ceph monitor (v2 msgr2)",
		6800: "Ceph OSD",
		6801: "Ceph OSD",
		7480: "Ceph RADOS Gateway",
		8443: "Ceph Dashboard (HTTPS)",
		8080: "Ceph Dashboard (HTTP)",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "ceph_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDefaultDashboardPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ceph_default_password",
			Message: fmt.Sprintf("service %q: Ceph dashboard uses default/weak password", svc.Name),
		})
	}

	if isDemoMode(envs, svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ceph_demo_mode",
			Message: fmt.Sprintf("service %q: Ceph running in demo mode", svc.Name),
		})
	}

	if hasDebugEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "ceph_debug_enabled",
			Message: fmt.Sprintf("service %q: Ceph debug logging enabled — may leak sensitive data", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isCephImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "ceph_no_auth":
					r.Summary.NoAuth++
				case "ceph_partial_auth":
					r.Summary.PartialAuth++
				case "ceph_no_encryption":
					r.Summary.NoEncryption++
				case "ceph_exposed_port":
					r.Summary.ExposedPort++
				case "ceph_default_password":
					r.Summary.DefaultPassword++
				case "ceph_demo_mode":
					r.Summary.DemoMode++
				case "ceph_debug_enabled":
					r.Summary.DebugEnabled++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Ceph Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Ceph services found.\n")
		return b.String()
	}

	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  Service: %s\n", svc.Service)
		if len(svc.Findings) == 0 {
			b.WriteString("    No findings.\n")
		}
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  Summary: no_auth=%d partial_auth=%d no_encryption=%d exposed_port=%d default_password=%d demo_mode=%d debug=%d\n",
		r.Summary.NoAuth, r.Summary.PartialAuth, r.Summary.NoEncryption,
		r.Summary.ExposedPort, r.Summary.DefaultPassword, r.Summary.DemoMode, r.Summary.DebugEnabled)

	return b.String()
}
