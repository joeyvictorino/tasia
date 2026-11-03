package fdlimit

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestMissingNofile(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_missing_nofile" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_missing_nofile finding")
	}
}

func TestNofileSet(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "web",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 1024, Hard: 4096},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_missing_nofile" {
				t.Error("should not flag missing nofile when set")
			}
		}
	}
}

func TestHighNofileLimit(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "worker",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 2000000, Hard: 2000000},
		},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_high_nofile" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_high_nofile finding for limit >1M")
	}
}

func TestNofileNotHigh(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "app",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 65536, Hard: 65536},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_high_nofile" {
				t.Error("should not flag normal nofile limit")
			}
		}
	}
}

func TestSoftExceedsHard(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "svc",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 8192, Hard: 4096},
		},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_soft_exceeds_hard" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_soft_exceeds_hard finding")
	}
}

func TestHighNproc(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "proc-heavy",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 1024, Hard: 1024},
			"nproc":  {Soft: 200000, Hard: 200000},
		},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_high_nproc" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_high_nproc finding for nproc >100k")
	}
}

func TestHostPidFdLeak(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "hostpid",
		PidMode: "host",
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_host_pid_fd_leak" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_host_pid_fd_leak finding")
	}
}

func TestHostPidWithNofile(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "hostpid-safe",
		PidMode: "host",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 1024, Hard: 4096},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_host_pid_fd_leak" {
				t.Error("should not flag host pid when nofile set")
			}
		}
	}
}

func TestSocketExhaustion(t *testing.T) {
	ports := []compose.PortMapping{
		{HostPort: 8080, TargetPort: 8080},
		{HostPort: 8081, TargetPort: 8081},
		{HostPort: 8082, TargetPort: 8082},
		{HostPort: 8083, TargetPort: 8083},
		{HostPort: 8084, TargetPort: 8084},
		{HostPort: 8085, TargetPort: 8085},
	}
	c := makeCollected(compose.Service{
		Name:  "many-ports",
		Ports: ports,
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_socket_exhaustion" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_socket_exhaustion finding for >5 ports without limits")
	}
}

func TestSocketExhaustionWithLimits(t *testing.T) {
	ports := []compose.PortMapping{
		{HostPort: 8080, TargetPort: 8080},
		{HostPort: 8081, TargetPort: 8081},
		{HostPort: 8082, TargetPort: 8082},
		{HostPort: 8083, TargetPort: 8083},
		{HostPort: 8084, TargetPort: 8084},
		{HostPort: 8085, TargetPort: 8085},
	}
	c := makeCollected(compose.Service{
		Name:  "many-ports-safe",
		Ports: ports,
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 65536, Hard: 65536},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_socket_exhaustion" {
				t.Error("should not flag socket exhaustion when nofile set")
			}
		}
	}
}

func TestPipeAccumulation(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "pipe-svc",
		Volumes: []string{"/proc:/host-proc:ro"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_pipe_accumulation" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_pipe_accumulation finding")
	}
}

func TestPrivilegedNoLimit(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "priv-svc",
		Privileged: true,
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_privileged_no_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected fdlimit_privileged_no_limit finding")
	}
}

func TestPrivilegedWithLimit(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "priv-safe",
		Privileged: true,
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 1024, Hard: 4096},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "fdlimit_privileged_no_limit" {
				t.Error("should not flag privileged when nofile set")
			}
		}
	}
}

func TestSummaryCounters(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a"},
		compose.Service{Name: "b", Privileged: true},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingNofile != 2 {
		t.Errorf("expected 2 missing nofile, got %d", r.Summary.MissingNofile)
	}
	if r.Summary.PrivilegedFd != 1 {
		t.Errorf("expected 1 privileged fd, got %d", r.Summary.PrivilegedFd)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "File Descriptor") {
		t.Error("expected header in text output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", PidMode: "host"},
		compose.Service{
			Name: "b",
			Ulimits: map[string]compose.UlimitValue{
				"nofile": {Soft: 1024, Hard: 4096},
			},
		},
	)
	r := Analyze(c)
	if len(r.Services) != 2 {
		t.Errorf("expected 2 service results, got %d", len(r.Services))
	}
	if r.Summary.HostPidFdLeak != 1 {
		t.Errorf("expected 1 host pid fd leak, got %d", r.Summary.HostPidFdLeak)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
