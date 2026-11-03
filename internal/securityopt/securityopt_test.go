package securityopt

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestIsSeccompDisabled(t *testing.T) {
	tests := []struct {
		opt  string
		want bool
	}{
		{"seccomp=unconfined", true},
		{"seccomp:unconfined", true},
		{"SECCOMP=UNCONFINED", true},
		{"seccomp=default", false},
		{"apparmor=unconfined", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSeccompDisabled(tt.opt)
		if got != tt.want {
			t.Errorf("isSeccompDisabled(%q) = %v, want %v", tt.opt, got, tt.want)
		}
	}
}

func TestIsAppArmorDisabled(t *testing.T) {
	tests := []struct {
		opt  string
		want bool
	}{
		{"apparmor=unconfined", true},
		{"apparmor:unconfined", true},
		{"APPARMOR=UNCONFINED", true},
		{"apparmor=docker-default", false},
		{"seccomp=unconfined", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isAppArmorDisabled(tt.opt)
		if got != tt.want {
			t.Errorf("isAppArmorDisabled(%q) = %v, want %v", tt.opt, got, tt.want)
		}
	}
}

func TestIsSELinuxDisabled(t *testing.T) {
	tests := []struct {
		opt  string
		want bool
	}{
		{"label=disable", true},
		{"label:disable", true},
		{"LABEL=DISABLE", true},
		{"label=level:s0", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSELinuxDisabled(tt.opt)
		if got != tt.want {
			t.Errorf("isSELinuxDisabled(%q) = %v, want %v", tt.opt, got, tt.want)
		}
	}
}

func TestHasSeccompProfile(t *testing.T) {
	tests := []struct {
		opts []string
		want bool
	}{
		{[]string{"seccomp=default"}, true},
		{[]string{"seccomp:default"}, true},
		{[]string{"apparmor=docker-default"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasSeccompProfile(tt.opts)
		if got != tt.want {
			t.Errorf("hasSeccompProfile(%v) = %v, want %v", tt.opts, got, tt.want)
		}
	}
}

func TestHasAppArmorProfile(t *testing.T) {
	tests := []struct {
		opts []string
		want bool
	}{
		{[]string{"apparmor=docker-default"}, true},
		{[]string{"seccomp=default"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasAppArmorProfile(tt.opts)
		if got != tt.want {
			t.Errorf("hasAppArmorProfile(%v) = %v, want %v", tt.opts, got, tt.want)
		}
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	s.SecurityOpt = []string{"seccomp=default", "apparmor=docker-default"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		if len(sr.Findings) != 0 {
			t.Fatalf("clean service should have no findings, got %d", len(sr.Findings))
		}
	}
}

func TestSeccompDisabled(t *testing.T) {
	s := svc("agent")
	s.SecurityOpt = []string{"seccomp=unconfined"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "seccomp_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected seccomp_disabled finding")
	}
}

func TestAppArmorDisabled(t *testing.T) {
	s := svc("worker")
	s.SecurityOpt = []string{"apparmor=unconfined"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "apparmor_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected apparmor_disabled finding")
	}
}

func TestSELinuxDisabled(t *testing.T) {
	s := svc("db")
	s.SecurityOpt = []string{"label=disable"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "selinux_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected selinux_disabled finding")
	}
}

func TestNoSecurityOpts(t *testing.T) {
	s := svc("api")
	s.CapAdd = []string{"NET_BIND_SERVICE"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_security_opts" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_security_opts finding")
	}
}

func TestPrivilegedNoSeccomp(t *testing.T) {
	s := svc("debug")
	s.Privileged = true
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "privileged_no_seccomp" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected privileged_no_seccomp finding")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("agent")
	s.SecurityOpt = []string{"seccomp=unconfined", "apparmor=unconfined", "label=disable"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.SeccompDisabled < 1 {
		t.Fatal("expected seccomp disabled count > 0")
	}
	if r.Summary.AppArmorDisabled < 1 {
		t.Fatal("expected apparmor disabled count > 0")
	}
	if r.Summary.SELinuxDisabled < 1 {
		t.Fatal("expected selinux disabled count > 0")
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("agent")
	s1.SecurityOpt = []string{"seccomp=unconfined"}
	s2 := svc("web")
	s2.SecurityOpt = []string{"seccomp=default"}
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in text")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("debug")
	s.SecurityOpt = []string{"seccomp=unconfined"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "debug") {
		t.Fatal("expected service name")
	}
	if !strings.Contains(text, "Security Options") {
		t.Fatal("expected header")
	}
}

func TestFormatJSON(t *testing.T) {
	s := svc("web")
	s.SecurityOpt = []string{"seccomp=default"}
	c := collected(s)
	r := Analyze(c)
	out := FormatJSON(r)
	if !strings.Contains(out, "web") {
		t.Fatal("expected service in JSON")
	}
}
