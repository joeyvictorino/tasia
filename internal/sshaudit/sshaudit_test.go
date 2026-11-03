package sshaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string, opts ...func(*compose.Service)) compose.Service {
	s := compose.Service{Name: name}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func withEnv(envs ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Environment = append(s.Environment, envs...)
	}
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Image = img
	}
}

func withPorts(ports ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		for _, p := range ports {
			s.Ports = append(s.Ports, compose.PortMapping{Raw: p})
		}
	}
}

func withVolumes(vols ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Volumes = append(s.Volumes, vols...)
	}
}

func findRule(results []ServiceResult, ruleID string) *Finding {
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule == ruleID {
				return &f
			}
		}
	}
	return nil
}

func TestRootLoginEnabled(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("PERMIT_ROOT_LOGIN=true")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-001") == nil {
		t.Fatal("expected SSH-001 for root login")
	}
}

func TestRootLoginDisabled(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("PERMIT_ROOT_LOGIN=false")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-001") != nil {
		t.Fatal("unexpected SSH-001 when root login disabled")
	}
}

func TestPasswordAuthEnabled(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("PASSWORD_AUTH=true")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-002") == nil {
		t.Fatal("expected SSH-002 for password auth")
	}
}

func TestPasswordAuthDisabled(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("PASSWORD_AUTH=false")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-002") != nil {
		t.Fatal("unexpected SSH-002 when password auth disabled")
	}
}

func TestDefaultPort(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withPorts("2222:22")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-003") == nil {
		t.Fatal("expected SSH-003 for default port 22")
	}
}

func TestNonDefaultPort(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withPorts("2222:2222")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-003") != nil {
		t.Fatal("unexpected SSH-003 when not port 22")
	}
}

func TestNoHostKeys(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-004") == nil {
		t.Fatal("expected SSH-004 for missing host keys")
	}
}

func TestHostKeysMounted(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withVolumes("./keys:/etc/ssh/ssh_host_rsa_key")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-004") != nil {
		t.Fatal("unexpected SSH-004 when host keys mounted")
	}
}

func TestX11ForwardingEnabled(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("X11_FORWARDING=true")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-005") == nil {
		t.Fatal("expected SSH-005 for X11 forwarding")
	}
}

func TestEmptyPasswordsEnabled(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("PERMIT_EMPTY_PASSWORDS=true")))
	r := Analyze(c)
	if findRule(r.Results, "SSH-006") == nil {
		t.Fatal("expected SSH-006 for empty passwords")
	}
}

func TestNonSSHServiceIgnored(t *testing.T) {
	c := mkCollected(svc("postgres", withImage("postgres:15")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryAffectedCount(t *testing.T) {
	c := mkCollected(
		svc("ssh", withImage("openssh-server"), withEnv("PERMIT_ROOT_LOGIN=true")),
		svc("db", withImage("postgres:15")),
	)
	r := Analyze(c)
	if r.Summary.AffectedServices != 1 {
		t.Fatalf("expected 1 affected, got %d", r.Summary.AffectedServices)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"), withEnv("PERMIT_ROOT_LOGIN=true")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "SSH Server") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server")))
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "Results") {
		t.Fatal("expected Results in JSON")
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("openssh-server"),
		withEnv("PERMIT_ROOT_LOGIN=true", "PASSWORD_AUTH=true", "X11_FORWARDING=true"),
		withPorts("2222:22"),
	))
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestDropbearDetected(t *testing.T) {
	c := mkCollected(svc("ssh", withImage("dropbear:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for dropbear")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := mkCollected()
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}
