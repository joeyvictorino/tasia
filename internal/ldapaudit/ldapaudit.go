package ldapaudit

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
	PlaintextLDAP     int `json:"plaintext_ldap"`
	NoLDAPTLS         int `json:"no_ldap_tls"`
	AnonymousBind     int `json:"anonymous_bind"`
	WeakBindDN        int `json:"weak_bind_dn"`
	ExposedAdminPort  int `json:"exposed_admin_port"`
}

var ldapPorts = []int{389, 636, 3268, 3269, 1389}

var ldapImages = []string{
	"openldap", "osixia/openldap", "bitnami/openldap",
	"389ds", "freeipa", "glauth", "lldap",
	"ldap-service", "slapd", "apacheds",
}

func isLDAPService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range ldapImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ldap") {
			return true
		}
	}
	for _, p := range svc.Ports {
		for _, lp := range ldapPorts {
			if p.TargetPort == lp {
				return true
			}
		}
	}
	return false
}

func hasLDAPTLS(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ldap_tls") ||
			strings.Contains(lower, "ldaps") ||
			strings.Contains(lower, "ldap_ssl") ||
			strings.Contains(lower, "tls_cert") ||
			strings.Contains(lower, "ssl_cert") ||
			strings.Contains(lower, "starttls") {
			return true
		}
	}
	for _, p := range svc.Ports {
		if p.TargetPort == 636 || p.TargetPort == 3269 {
			return true
		}
	}
	return false
}

func hasAnonymousBind(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "anonymous_bind=true") ||
			strings.Contains(lower, "allow_anonymous") ||
			strings.Contains(lower, "anonymous=yes") ||
			strings.Contains(lower, "disable_auth") {
			return true
		}
	}
	return false
}

func hasWeakBindDN(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "bind_dn") || strings.Contains(lower, "admin_dn") {
			if strings.Contains(lower, "cn=admin") ||
				strings.Contains(lower, "cn=root") ||
				strings.Contains(lower, "cn=manager") {
				return true
			}
		}
	}
	return false
}

func hasPublicPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func hasPlaintextPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 389 && p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func hasAdminPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if (p.TargetPort == 8080 || p.TargetPort == 8443 || p.TargetPort == 4443 || p.TargetPort == 6443 || p.TargetPort == 17170) && p.IsAllInterfaces() {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "admin_port") || strings.Contains(lower, "phpldapadmin") || strings.Contains(lower, "ldap_admin") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isLDAPService(svc) {
		return sr
	}

	if hasPlaintextPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "plaintext_ldap",
			Message: fmt.Sprintf("LDAP service '%s' exposes plaintext port 389 publicly; credentials and directory data are transmitted unencrypted", svc.Name),
		})
	}

	if !hasLDAPTLS(svc) && hasPublicPort(svc) && !hasPlaintextPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_ldap_tls",
			Message: fmt.Sprintf("LDAP service '%s' is publicly exposed without TLS/STARTTLS configuration; enable LDAPS or STARTTLS to encrypt directory traffic", svc.Name),
		})
	}

	if hasAnonymousBind(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "anonymous_bind",
			Message: fmt.Sprintf("LDAP service '%s' allows anonymous bind; unauthenticated users can query the directory and enumerate entries", svc.Name),
		})
	}

	if hasWeakBindDN(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "weak_bind_dn",
			Message: fmt.Sprintf("LDAP service '%s' uses a well-known admin bind DN on a public port; attackers can target default admin credentials", svc.Name),
		})
	}

	if hasAdminPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "exposed_admin_port",
			Message: fmt.Sprintf("LDAP service '%s' exposes an admin/management port publicly; restrict admin interfaces to internal networks", svc.Name),
		})
	}

	return sr
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "plaintext_ldap":
				s.PlaintextLDAP++
			case "no_ldap_tls":
				s.NoLDAPTLS++
			case "anonymous_bind":
				s.AnonymousBind++
			case "weak_bind_dn":
				s.WeakBindDN++
			case "exposed_admin_port":
				s.ExposedAdminPort++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LDAP Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Plaintext LDAP:              %d\n", r.Summary.PlaintextLDAP)
	fmt.Fprintf(&b, "  Missing LDAP TLS:            %d\n", r.Summary.NoLDAPTLS)
	fmt.Fprintf(&b, "  Anonymous bind:              %d\n", r.Summary.AnonymousBind)
	fmt.Fprintf(&b, "  Weak bind DN:                %d\n", r.Summary.WeakBindDN)
	fmt.Fprintf(&b, "  Exposed admin port:          %d\n\n", r.Summary.ExposedAdminPort)
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
