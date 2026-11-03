package dbus

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
	SystemBusExposed    int `json:"system_bus_exposed"`
	SessionBusExposed   int `json:"session_bus_exposed"`
	DBusSocketMounted   int `json:"dbus_socket_mounted"`
	PrivilegedDBusAccess int `json:"privileged_dbus_access"`
}

var systemBusPaths = []string{
	"/var/run/dbus/system_bus_socket",
	"/run/dbus/system_bus_socket",
	"/var/run/dbus",
	"/run/dbus",
}

var sessionBusPaths = []string{
	"/run/user/", "/tmp/dbus-",
}

func isSystemBusPath(path string) bool {
	for _, sp := range systemBusPaths {
		if path == sp || strings.HasPrefix(path, sp+"/") {
			return true
		}
	}
	return false
}

func isSessionBusPath(path string) bool {
	for _, sp := range sessionBusPaths {
		if strings.HasPrefix(path, sp) {
			return true
		}
	}
	return false
}

func isDBusEnv(env string) bool {
	upper := strings.ToUpper(env)
	return strings.HasPrefix(upper, "DBUS_SYSTEM_BUS_ADDRESS=") ||
		strings.HasPrefix(upper, "DBUS_SESSION_BUS_ADDRESS=")
}

func extractVolumeSrc(vol string) string {
	parts := strings.SplitN(vol, ":", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return vol
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

	for _, vol := range svc.Volumes {
		src := extractVolumeSrc(vol)
		if isSystemBusPath(src) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "system_bus_exposed",
				Message: fmt.Sprintf("Service '%s' mounts D-Bus system bus socket '%s'; container can communicate with host system services and potentially escalate privileges", svc.Name, vol),
			})
		}
		if isSessionBusPath(src) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "session_bus_exposed",
				Message: fmt.Sprintf("Service '%s' mounts D-Bus session bus path '%s'; container can interact with user session services", svc.Name, vol),
			})
		}
	}

	for _, env := range svc.Environment {
		if isDBusEnv(env) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dbus_socket_mounted",
				Message: fmt.Sprintf("Service '%s' configures D-Bus address via environment (%s); may expose host D-Bus to container", svc.Name, env),
			})
			break
		}
	}

	for _, cap := range svc.CapAdd {
		upper := strings.ToUpper(strings.TrimSpace(cap))
		if upper == "SYS_ADMIN" || upper == "ALL" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "privileged_dbus_access",
				Message: fmt.Sprintf("Service '%s' has %s capability with potential D-Bus access; can bypass D-Bus policy restrictions on the system bus", svc.Name, upper),
			})
			break
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
			case "system_bus_exposed":
				s.SystemBusExposed++
			case "session_bus_exposed":
				s.SessionBusExposed++
			case "dbus_socket_mounted":
				s.DBusSocketMounted++
			case "privileged_dbus_access":
				s.PrivilegedDBusAccess++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "D-Bus Socket Exposure Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  System bus exposed:      %d\n", r.Summary.SystemBusExposed)
	fmt.Fprintf(&b, "  Session bus exposed:     %d\n", r.Summary.SessionBusExposed)
	fmt.Fprintf(&b, "  D-Bus socket configured: %d\n", r.Summary.DBusSocketMounted)
	fmt.Fprintf(&b, "  Privileged D-Bus access: %d\n\n", r.Summary.PrivilegedDBusAccess)
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
