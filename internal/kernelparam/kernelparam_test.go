package kernelparam

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestNoDangerous(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "web"}))
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestDangerousSysctl(t *testing.T) {
	svc := compose.Service{
		Name:    "agent",
		Sysctls: map[string]string{"kernel.core_pattern": "|/tmp/exploit"},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "kparam_dangerous_sysctl" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected kparam_dangerous_sysctl finding")
	}
}

func TestCorePattern(t *testing.T) {
	svc := compose.Service{
		Name:    "agent",
		Sysctls: map[string]string{"kernel.core_pattern": "|/exploit"},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "kparam_core_pattern" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected kparam_core_pattern finding")
	}
}

func TestNetworkForwarding(t *testing.T) {
	svc := compose.Service{
		Name:    "router",
		Sysctls: map[string]string{"net.ipv4.ip_forward": "1"},
	}
	r := Analyze(collected(svc))
	if r.Summary.NetworkForwarding == 0 {
		t.Error("expected network forwarding finding")
	}
}

func TestNetworkForwardingDisabled(t *testing.T) {
	svc := compose.Service{
		Name:    "router",
		Sysctls: map[string]string{"net.ipv4.ip_forward": "0"},
	}
	r := Analyze(collected(svc))
	if r.Summary.NetworkForwarding != 0 {
		t.Error("expected no network forwarding finding when disabled")
	}
}

func TestIPv6Forwarding(t *testing.T) {
	svc := compose.Service{
		Name:    "router",
		Sysctls: map[string]string{"net.ipv6.conf.all.forwarding": "1"},
	}
	r := Analyze(collected(svc))
	if r.Summary.NetworkForwarding == 0 {
		t.Error("expected IPv6 forwarding finding")
	}
}

func TestPrivilegedWithSysctl(t *testing.T) {
	svc := compose.Service{
		Name:       "dangerous",
		Privileged: true,
		Sysctls:    map[string]string{"net.core.somaxconn": "65535"},
	}
	r := Analyze(collected(svc))
	if r.Summary.PrivilegedSysctl == 0 {
		t.Error("expected privileged sysctl finding")
	}
}

func TestPrivilegedNoSysctl(t *testing.T) {
	svc := compose.Service{
		Name:       "dangerous",
		Privileged: true,
	}
	r := Analyze(collected(svc))
	if r.Summary.UnrestrictedSysctl == 0 {
		t.Error("expected unrestricted privileged finding")
	}
}

func TestShmOverride(t *testing.T) {
	svc := compose.Service{
		Name:    "db",
		Sysctls: map[string]string{"kernel.shmmax": "68719476736"},
	}
	r := Analyze(collected(svc))
	if r.Summary.ShmParams == 0 {
		t.Error("expected shm param finding")
	}
}

func TestShmAll(t *testing.T) {
	svc := compose.Service{
		Name:    "db",
		Sysctls: map[string]string{"kernel.shmall": "4294967296"},
	}
	r := Analyze(collected(svc))
	if r.Summary.ShmParams == 0 {
		t.Error("expected shm param finding for shmall")
	}
}

func TestMultipleSysctls(t *testing.T) {
	svc := compose.Service{
		Name: "multi",
		Sysctls: map[string]string{
			"kernel.core_pattern":  "|/exploit",
			"net.ipv4.ip_forward": "1",
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings for multiple dangerous sysctls, got %d", r.Summary.TotalFindings)
	}
}

func TestSafeSysctl(t *testing.T) {
	svc := compose.Service{
		Name:    "safe",
		Sysctls: map[string]string{"net.core.somaxconn": "1024"},
	}
	r := Analyze(collected(svc))
	if r.Summary.DangerousSysctl != 0 {
		t.Error("net.core.somaxconn should not be flagged as dangerous")
	}
}

func TestNoSysctlNoFindings(t *testing.T) {
	svc := compose.Service{
		Name:  "clean",
		Image: "nginx:latest",
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{
		Name:    "svc1",
		Sysctls: map[string]string{"kernel.core_pattern": "|/a"},
	}
	svc2 := compose.Service{
		Name:    "svc2",
		Sysctls: map[string]string{"net.ipv4.ip_forward": "1"},
	}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings across services, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name:    "agent",
		Sysctls: map[string]string{"kernel.core_pattern": "|/exploit"},
	}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "Kernel Parameter Audit") {
		t.Error("expected header in output")
	}
	if !contains(text, "core_pattern") {
		t.Error("expected core_pattern reference in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "clean"}))
	text := FormatText(r)
	if !contains(text, "0 findings") {
		t.Error("expected 0 findings in output")
	}
}

func TestKernelModprobe(t *testing.T) {
	svc := compose.Service{
		Name:    "agent",
		Sysctls: map[string]string{"kernel.modprobe": "/sbin/modprobe"},
	}
	r := Analyze(collected(svc))
	if r.Summary.DangerousSysctl == 0 {
		t.Error("expected dangerous sysctl for kernel.modprobe")
	}
}

func TestASLRDisable(t *testing.T) {
	svc := compose.Service{
		Name:    "agent",
		Sysctls: map[string]string{"kernel.randomize_va_space": "0"},
	}
	r := Analyze(collected(svc))
	if r.Summary.DangerousSysctl == 0 {
		t.Error("expected dangerous sysctl for ASLR disable")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
