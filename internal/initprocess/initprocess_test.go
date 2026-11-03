package initprocess

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs []compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestServiceWithInit(t *testing.T) {
	svcs := []compose.Service{{Name: "web", Init: true, Restart: "always"}}
	r := Analyze(collected(svcs))
	if r.Summary.WithInit != 1 {
		t.Fatalf("expected 1 with init, got %d", r.Summary.WithInit)
	}
}

func TestMissingInit(t *testing.T) {
	svcs := []compose.Service{{Name: "web", Restart: "always"}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_missing" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_missing finding for long-running service")
	}
}

func TestMissingInitWithPorts(t *testing.T) {
	svcs := []compose.Service{{Name: "api", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_missing" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_missing finding for service with ports")
	}
}

func TestInteractiveMode(t *testing.T) {
	svcs := []compose.Service{{Name: "debug", Tty: true, StdinOpen: true}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_interactive" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_interactive finding")
	}
}

func TestNoGracePeriod(t *testing.T) {
	svcs := []compose.Service{{Name: "web", Restart: "always"}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_no_grace_period" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_no_grace_period finding")
	}
}

func TestShortGracePeriod(t *testing.T) {
	svcs := []compose.Service{{Name: "web", StopGracePeriod: "1s", Restart: "always"}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_short_grace" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_short_grace finding")
	}
}

func TestPrivilegedNoInit(t *testing.T) {
	svcs := []compose.Service{{Name: "agent", Privileged: true}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_privileged_no_init" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_privileged_no_init finding")
	}
}

func TestTtyNoInit(t *testing.T) {
	svcs := []compose.Service{{Name: "worker", Tty: true}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_tty_no_init" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_tty_no_init finding")
	}
}

func TestNoIssuesWithInit(t *testing.T) {
	svcs := []compose.Service{{Name: "web", Init: true, Restart: "always", StopGracePeriod: "30s"}}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for properly configured service, got %d", r.Summary.TotalFindings)
	}
}

func TestCounters(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", Init: true, Tty: true, StdinOpen: true},
		{Name: "b", Tty: false, StdinOpen: false},
	}
	r := Analyze(collected(svcs))
	if r.Summary.WithInit != 1 {
		t.Fatalf("expected 1 with init, got %d", r.Summary.WithInit)
	}
	if r.Summary.WithTty != 1 {
		t.Fatalf("expected 1 with tty, got %d", r.Summary.WithTty)
	}
	if r.Summary.WithStdin != 1 {
		t.Fatalf("expected 1 with stdin, got %d", r.Summary.WithStdin)
	}
}

func TestFormatText(t *testing.T) {
	svcs := []compose.Service{{Name: "web", Restart: "always"}}
	r := Analyze(collected(svcs))
	text := FormatText(r)
	if !strings.Contains(text, "Init Process") {
		t.Fatal("expected header")
	}
	if !strings.Contains(text, "init_missing") {
		t.Fatal("expected finding in output")
	}
}

func TestHealthcheckMeansLongRunning(t *testing.T) {
	hc := &compose.Healthcheck{Test: []string{"CMD", "curl", "-f", "http://localhost"}}
	svcs := []compose.Service{{Name: "web", Healthcheck: hc}}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "init_missing" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected init_missing for service with healthcheck")
	}
}
