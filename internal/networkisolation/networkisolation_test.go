package networkisolation

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

func makeCollectedWithNetwork(nets map[string]compose.Network, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs, Networks: nets},
		},
	}
}

func TestHostNetwork(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "proxy",
		NetworkMode: "host",
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_host_network" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected networkisolation_host_network finding")
	}
}

func TestHostNetworkNoInternalSkipped(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "proxy",
		NetworkMode: "host",
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_no_internal" {
				t.Error("should not flag no-internal for host network mode")
			}
		}
	}
}

func TestNoInternalNetwork(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_no_internal" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected networkisolation_no_internal finding")
	}
}

func TestInternalNetworkPresent(t *testing.T) {
	nets := map[string]compose.Network{
		"backend": {Internal: true},
	}
	c := makeCollectedWithNetwork(nets, compose.Service{Name: "web"})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_no_internal" {
				t.Error("should not flag when internal network exists")
			}
		}
	}
}

func TestWildcardBind(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "api",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080, HostIP: ""},
		},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_wildcard_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected networkisolation_wildcard_bind finding")
	}
}

func TestLocalBind(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "api",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080, HostIP: "127.0.0.1"},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_wildcard_bind" {
				t.Error("should not flag 127.0.0.1 bind")
			}
		}
	}
}

func TestHighPortExposure(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "debug",
		Ports: []compose.PortMapping{
			{HostPort: 40000, TargetPort: 40000, HostIP: "127.0.0.1"},
		},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_high_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected networkisolation_high_port finding")
	}
}

func TestNormalPort(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080, HostIP: "127.0.0.1"},
		},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_high_port" {
				t.Error("should not flag normal port")
			}
		}
	}
}

func TestMissingDNSConfig(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_no_dns_config" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected networkisolation_no_dns_config finding")
	}
}

func TestDNSConfigSet(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "app",
		DNS:  []string{"8.8.8.8"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_no_dns_config" {
				t.Error("should not flag when DNS is configured")
			}
		}
	}
}

func TestHostIPC(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "shm-svc",
		IpcMode: "host",
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_host_ipc" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected networkisolation_host_ipc finding")
	}
}

func TestNonHostIPC(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "svc",
		IpcMode: "private",
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_host_ipc" {
				t.Error("should not flag non-host IPC")
			}
		}
	}
}

func TestSummaryCounters(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", NetworkMode: "host"},
		compose.Service{Name: "b", IpcMode: "host"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.HostNetwork != 1 {
		t.Errorf("expected 1 host network, got %d", r.Summary.HostNetwork)
	}
	if r.Summary.HostIPC != 1 {
		t.Errorf("expected 1 host IPC, got %d", r.Summary.HostIPC)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "Network Isolation") {
		t.Error("expected header in text output")
	}
}

func TestNetworkModeNone(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "isolated",
		NetworkMode: "none",
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "networkisolation_no_internal" {
				t.Error("should not flag no-internal for network mode none")
			}
			if f.Rule == "networkisolation_no_dns_config" {
				t.Error("should not flag missing DNS for network mode none")
			}
		}
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
