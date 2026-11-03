package ambient

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

func TestIsDangerous(t *testing.T) {
	tests := []struct {
		cap  string
		want bool
	}{
		{"SYS_ADMIN", true},
		{"SYS_PTRACE", true},
		{"NET_ADMIN", true},
		{"NET_RAW", true},
		{"CHOWN", false},
		{"KILL", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isDangerous(tt.cap)
		if got != tt.want {
			t.Errorf("isDangerous(%q) = %v, want %v", tt.cap, got, tt.want)
		}
	}
}

func TestHasNoNewPrivileges(t *testing.T) {
	tests := []struct {
		opts []string
		want bool
	}{
		{[]string{"no-new-privileges"}, true},
		{[]string{"no-new-privileges:true"}, true},
		{[]string{"no-new-privileges=true"}, true},
		{[]string{"seccomp=unconfined"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasNoNewPrivileges(tt.opts)
		if got != tt.want {
			t.Errorf("hasNoNewPrivileges(%v) = %v, want %v", tt.opts, got, tt.want)
		}
	}
}

func TestHasCapDropAll(t *testing.T) {
	tests := []struct {
		caps []string
		want bool
	}{
		{[]string{"ALL"}, true},
		{[]string{"all"}, true},
		{[]string{"NET_RAW"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasCapDropAll(tt.caps)
		if got != tt.want {
			t.Errorf("hasCapDropAll(%v) = %v, want %v", tt.caps, got, tt.want)
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
	s.CapDrop = []string{"ALL"}
	s.CapAdd = []string{"NET_BIND_SERVICE"}
	s.SecurityOpt = []string{"no-new-privileges"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		if len(sr.Findings) != 0 {
			t.Fatalf("clean service should have no findings, got %d", len(sr.Findings))
		}
	}
}

func TestDangerousCapAdded(t *testing.T) {
	s := svc("agent")
	s.CapAdd = []string{"SYS_ADMIN"}
	s.CapDrop = []string{"ALL"}
	s.SecurityOpt = []string{"no-new-privileges"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "dangerous_cap_added" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected dangerous_cap_added finding")
	}
}

func TestNoNewPrivsMissing(t *testing.T) {
	s := svc("worker")
	s.CapAdd = []string{"NET_BIND_SERVICE"}
	s.CapDrop = []string{"ALL"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_new_privs_missing" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_new_privs_missing finding")
	}
}

func TestCapDropMissing(t *testing.T) {
	s := svc("api")
	s.CapAdd = []string{"NET_BIND_SERVICE"}
	s.SecurityOpt = []string{"no-new-privileges"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cap_drop_missing" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected cap_drop_missing finding")
	}
}

func TestExcessiveCaps(t *testing.T) {
	s := svc("monster")
	s.CapAdd = []string{"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW", "DAC_OVERRIDE", "FOWNER"}
	s.CapDrop = []string{"ALL"}
	s.SecurityOpt = []string{"no-new-privileges"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "excessive_caps" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected excessive_caps finding")
	}
}

func TestPrivilegedWithCapDrop(t *testing.T) {
	s := svc("debug")
	s.Privileged = true
	s.CapDrop = []string{"NET_RAW"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "privileged_with_cap_drop" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected privileged_with_cap_drop finding")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("agent")
	s.CapAdd = []string{"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW", "DAC_OVERRIDE", "FOWNER"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.DangerousCaps < 1 {
		t.Fatal("expected dangerous caps count > 0")
	}
	if r.Summary.TotalFindings < 1 {
		t.Fatal("expected total findings > 0")
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("agent")
	s1.CapAdd = []string{"SYS_ADMIN"}
	s2 := svc("web")
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
	s.CapAdd = []string{"SYS_ADMIN"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "debug") {
		t.Fatal("expected service name in text")
	}
	if !strings.Contains(text, "Ambient") {
		t.Fatal("expected header")
	}
}

func TestFormatJSON(t *testing.T) {
	s := svc("web")
	s.CapAdd = []string{"NET_BIND_SERVICE"}
	c := collected(s)
	r := Analyze(c)
	out := FormatJSON(r)
	if !strings.Contains(out, "web") {
		t.Fatal("expected service in JSON")
	}
}
