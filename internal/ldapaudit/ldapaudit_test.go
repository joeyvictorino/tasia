package ldapaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path:     "docker-compose.yml",
			Services: services,
		}},
	}
}

func svc(name, image string) compose.Service {
	return compose.Service{Name: name, Image: image}
}

func publicPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target}
}

func localhostPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target, HostIP: "127.0.0.1"}
}

func findByRule(services []ServiceResult, rule string) []Finding {
	var found []Finding
	for _, sr := range services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				found = append(found, f)
			}
		}
	}
	return found
}

func TestPlaintextLDAPPublicPort(t *testing.T) {
	s := compose.Service{
		Name:  "ldap",
		Image: "osixia/openldap:latest",
		Ports: []compose.PortMapping{publicPort(389, 389)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_ldap")
	if len(findings) == 0 {
		t.Fatal("expected plaintext_ldap finding for public LDAP on port 389")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestPlaintextLDAPLocalhostNotFlagged(t *testing.T) {
	s := compose.Service{
		Name:  "ldap",
		Image: "osixia/openldap:latest",
		Ports: []compose.PortMapping{localhostPort(389, 389)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "plaintext_ldap")
	if len(findings) != 0 {
		t.Fatal("should not flag plaintext_ldap on localhost binding")
	}
}

func TestNoLDAPTLSPublic(t *testing.T) {
	s := compose.Service{
		Name:  "ldap",
		Image: "bitnami/openldap:latest",
		Ports: []compose.PortMapping{publicPort(1389, 1389)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_ldap_tls")
	if len(findings) == 0 {
		t.Fatal("expected no_ldap_tls for public LDAP without TLS config")
	}
}

func TestNoLDAPTLSWithTLSConfig(t *testing.T) {
	s := compose.Service{
		Name:        "ldap",
		Image:       "osixia/openldap:latest",
		Ports:       []compose.PortMapping{publicPort(636, 636)},
		Environment: []string{"LDAP_TLS_CRT_FILENAME=cert.pem"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_ldap_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag no_ldap_tls when TLS is configured")
	}
}

func TestNoLDAPTLSWithLDAPSPort(t *testing.T) {
	s := compose.Service{
		Name:  "ldap",
		Image: "osixia/openldap:latest",
		Ports: []compose.PortMapping{publicPort(636, 636)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_ldap_tls")
	if len(findings) != 0 {
		t.Fatal("should not flag no_ldap_tls when LDAPS port 636 is used")
	}
}

func TestAnonymousBindFlagged(t *testing.T) {
	s := compose.Service{
		Name:        "ldap",
		Image:       "osixia/openldap:latest",
		Ports:       []compose.PortMapping{publicPort(389, 389)},
		Environment: []string{"LDAP_ANONYMOUS_BIND=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "anonymous_bind")
	if len(findings) == 0 {
		t.Fatal("expected anonymous_bind finding")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestAnonymousBindAllowAnonymous(t *testing.T) {
	s := compose.Service{
		Name:        "ldap",
		Image:       "glauth/glauth:latest",
		Ports:       []compose.PortMapping{publicPort(389, 389)},
		Environment: []string{"ALLOW_ANONYMOUS=yes"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "anonymous_bind")
	if len(findings) == 0 {
		t.Fatal("expected anonymous_bind for ALLOW_ANONYMOUS")
	}
}

func TestWeakBindDNPublic(t *testing.T) {
	s := compose.Service{
		Name:        "ldap",
		Image:       "osixia/openldap:latest",
		Ports:       []compose.PortMapping{publicPort(389, 389)},
		Environment: []string{"LDAP_ADMIN_DN=cn=admin,dc=example,dc=org"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_bind_dn")
	if len(findings) == 0 {
		t.Fatal("expected weak_bind_dn for cn=admin on public port")
	}
	if findings[0].Level != "medium" {
		t.Fatalf("expected medium severity, got %s", findings[0].Level)
	}
}

func TestWeakBindDNLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "ldap",
		Image:       "osixia/openldap:latest",
		Ports:       []compose.PortMapping{localhostPort(389, 389)},
		Environment: []string{"LDAP_ADMIN_DN=cn=admin,dc=example,dc=org"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_bind_dn")
	if len(findings) != 0 {
		t.Fatal("should not flag weak_bind_dn on localhost")
	}
}

func TestExposedAdminPort(t *testing.T) {
	s := compose.Service{
		Name:  "ldap-admin",
		Image: "osixia/phpldapadmin:latest",
		Ports: []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"PHPLDAPADMIN_LDAP_HOSTS=ldap"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "exposed_admin_port")
	if len(findings) == 0 {
		t.Fatal("expected exposed_admin_port for phpldapadmin on public 8080")
	}
}

func TestExposedAdminPortLocalhost(t *testing.T) {
	s := compose.Service{
		Name:  "ldap-admin",
		Image: "osixia/phpldapadmin:latest",
		Ports: []compose.PortMapping{localhostPort(8080, 8080)},
		Environment: []string{"PHPLDAPADMIN_LDAP_HOSTS=ldap"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "exposed_admin_port")
	if len(findings) == 0 {
		t.Fatal("expected exposed_admin_port from env var detection even on localhost port")
	}
}

func TestNonLDAPServiceNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-LDAP service, got %d", r.Summary.TotalFindings)
	}
}

func TestLDAPDetectedByPort(t *testing.T) {
	s := compose.Service{
		Name:  "svc",
		Image: "myapp:latest",
		Ports: []compose.PortMapping{publicPort(389, 389)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service uses LDAP port 389")
	}
}

func TestLDAPDetectedByEnv(t *testing.T) {
	s := compose.Service{
		Name:        "svc",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"LDAP_URI=ldap://ldap:389"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings when service has LDAP in env")
	}
}

func TestLDAPDetectedByImage(t *testing.T) {
	s := compose.Service{
		Name:  "directory",
		Image: "389ds/dirsrv:latest",
		Ports: []compose.PortMapping{publicPort(3389, 389)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for 389ds image")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s1 := compose.Service{
		Name:        "ldap",
		Image:       "osixia/openldap:latest",
		Ports:       []compose.PortMapping{publicPort(389, 389)},
		Environment: []string{"LDAP_ANONYMOUS_BIND=true"},
	}
	s2 := svc("redis", "redis:7")
	r := Analyze(collected(s1, s2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected at least 1 finding")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("ldap", "osixia/openldap:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "LDAP Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextContainsServiceName(t *testing.T) {
	s := compose.Service{
		Name:  "my-ldap-server",
		Image: "osixia/openldap:latest",
		Ports: []compose.PortMapping{publicPort(389, 389)},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-ldap-server") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("ldap", "osixia/openldap:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("ldap-dev", "bitnami/openldap:latest")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}

func TestGlobalCatalogPort(t *testing.T) {
	s := compose.Service{
		Name:  "ldap",
		Image: "osixia/openldap:latest",
		Ports: []compose.PortMapping{publicPort(3268, 3268)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for global catalog port 3268")
	}
}

func TestFreeIPADetection(t *testing.T) {
	s := compose.Service{
		Name:  "ipa",
		Image: "freeipa/freeipa-server:latest",
		Ports: []compose.PortMapping{publicPort(389, 389)},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for freeipa image")
	}
}

func TestLLDAPDetection(t *testing.T) {
	s := compose.Service{
		Name:  "auth",
		Image: "lldap/lldap:latest",
		Ports: []compose.PortMapping{publicPort(3890, 389), publicPort(17170, 17170)},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "exposed_admin_port")
	if len(findings) == 0 {
		t.Fatal("expected exposed_admin_port for lldap admin on 17170")
	}
}
