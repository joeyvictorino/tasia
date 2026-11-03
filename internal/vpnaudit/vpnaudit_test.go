package vpnaudit

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
	return func(s *compose.Service) { s.Environment = append(s.Environment, envs...) }
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) { s.Image = img }
}

func withPorts(ports ...compose.PortMapping) func(*compose.Service) {
	return func(s *compose.Service) { s.Ports = append(s.Ports, ports...) }
}

func withVolumes(vols ...string) func(*compose.Service) {
	return func(s *compose.Service) { s.Volumes = append(s.Volumes, vols...) }
}

func withPrivileged() func(*compose.Service) {
	return func(s *compose.Service) { s.Privileged = true }
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

func TestWeakCipherDES(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("VPN_CIPHER=DES-CBC")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-001") == nil {
		t.Fatal("expected VPN-001 for DES cipher")
	}
}

func TestWeakCipherNone(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("CIPHER=none")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-001") == nil {
		t.Fatal("expected VPN-001 for cipher=none")
	}
}

func TestStrongCipher(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("VPN_CIPHER=AES-256-GCM")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-001") != nil {
		t.Fatal("unexpected VPN-001 for AES-256-GCM")
	}
}

func TestNoAuthDisabled(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("VPN_AUTH=none")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-002") == nil {
		t.Fatal("expected VPN-002 for auth disabled")
	}
}

func TestAuthEnabled(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("VPN_AUTH=SHA256")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-002") != nil {
		t.Fatal("unexpected VPN-002 when auth enabled")
	}
}

func TestDefaultPort1194(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"),
		withPorts(compose.PortMapping{TargetPort: 1194, Raw: "1194:1194/udp"})))
	r := Analyze(c)
	if findRule(r.Results, "VPN-003") == nil {
		t.Fatal("expected VPN-003 for port 1194")
	}
}

func TestDefaultPort51820(t *testing.T) {
	c := mkCollected(svc("wg", withImage("wireguard"),
		withPorts(compose.PortMapping{TargetPort: 51820, Raw: "51820:51820/udp"})))
	r := Analyze(c)
	if findRule(r.Results, "VPN-003") == nil {
		t.Fatal("expected VPN-003 for WireGuard port 51820")
	}
}

func TestNonDefaultPort(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"),
		withPorts(compose.PortMapping{TargetPort: 8443, Raw: "8443:8443"})))
	r := Analyze(c)
	if findRule(r.Results, "VPN-003") != nil {
		t.Fatal("unexpected VPN-003 for non-default port")
	}
}

func TestTLSDisabled(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("TLS_AUTH=disabled")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-004") == nil {
		t.Fatal("expected VPN-004 for TLS disabled")
	}
}

func TestTLSEnabled(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("TLS_AUTH=true")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-004") != nil {
		t.Fatal("unexpected VPN-004 when TLS enabled")
	}
}

func TestPrivilegedMode(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withPrivileged()))
	r := Analyze(c)
	if findRule(r.Results, "VPN-005") == nil {
		t.Fatal("expected VPN-005 for privileged mode")
	}
}

func TestNonPrivileged(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-005") != nil {
		t.Fatal("unexpected VPN-005 when not privileged")
	}
}

func TestNoKeyVolume(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-006") == nil {
		t.Fatal("expected VPN-006 for missing key volume")
	}
}

func TestKeyVolumeMounted(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withVolumes("./certs:/etc/openvpn/pki")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-006") != nil {
		t.Fatal("unexpected VPN-006 when key volume mounted")
	}
}

func TestWireGuardConfVolume(t *testing.T) {
	c := mkCollected(svc("wg", withImage("wireguard"), withVolumes("./wg0.conf:/etc/wireguard/wg0.conf")))
	r := Analyze(c)
	if findRule(r.Results, "VPN-006") != nil {
		t.Fatal("unexpected VPN-006 when wg0.conf mounted")
	}
}

func TestNonVPNServiceIgnored(t *testing.T) {
	c := mkCollected(svc("db", withImage("postgres:15")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestIsVPNService(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"kylemanna/openvpn", true},
		{"linuxserver/wireguard", true},
		{"strongswan/charon", true},
		{"vpn-server:latest", true},
		{"softether/vpnserver", true},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		s := compose.Service{Image: tt.image}
		if got := isVPNService(s); got != tt.want {
			t.Errorf("isVPNService(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	c := mkCollected(
		svc("vpn", withImage("openvpn"), withEnv("VPN_CIPHER=DES-CBC"), withPrivileged()),
		svc("db", withImage("postgres:15")),
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.AffectedServices != 1 {
		t.Fatalf("expected 1 affected, got %d", r.Summary.AffectedServices)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn"), withEnv("VPN_AUTH=none")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "VPN Server") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := mkCollected(svc("vpn", withImage("openvpn")))
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "Results") {
		t.Fatal("expected Results in JSON")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := mkCollected()
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestIPSecPort500(t *testing.T) {
	c := mkCollected(svc("ipsec", withImage("strongswan"),
		withPorts(compose.PortMapping{TargetPort: 500, Raw: "500:500/udp"})))
	r := Analyze(c)
	if findRule(r.Results, "VPN-003") == nil {
		t.Fatal("expected VPN-003 for IPSec port 500")
	}
}
