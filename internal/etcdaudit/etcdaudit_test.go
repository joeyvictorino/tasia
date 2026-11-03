package etcdaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestEtcdMissingClientTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_client_tls" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_client_tls finding")
	}
}

func TestEtcdWithClientTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "bitnami/etcd:3.5",
		Environment: []string{
			"ETCD_CERT_FILE=/certs/server.crt",
			"ETCD_KEY_FILE=/certs/server.key",
			"ETCD_ROOT_PASSWORD=securepass",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_client_tls" {
				t.Error("should not flag missing_client_tls when cert is configured")
			}
		}
	}
}

func TestEtcdAutoTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
		Environment: []string{
			"ETCD_AUTO_TLS=true",
			"ETCD_ROOT_PASSWORD=securepass",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_client_tls" {
				t.Error("should not flag missing_client_tls when auto-tls is true")
			}
		}
	}
}

func TestEtcdMissingPeerTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "bitnami/etcd:3.5",
		Environment: []string{
			"ETCD_CERT_FILE=/certs/server.crt",
			"ETCD_KEY_FILE=/certs/server.key",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_peer_tls" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_peer_tls finding")
	}
}

func TestEtcdWithPeerTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "bitnami/etcd:3.5",
		Environment: []string{
			"ETCD_CERT_FILE=/certs/server.crt",
			"ETCD_KEY_FILE=/certs/server.key",
			"ETCD_PEER_CERT_FILE=/certs/peer.crt",
			"ETCD_PEER_KEY_FILE=/certs/peer.key",
			"ETCD_ROOT_PASSWORD=securepass",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_peer_tls" {
				t.Error("should not flag missing_peer_tls when peer certs are configured")
			}
		}
	}
}

func TestEtcdMissingAuth(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_auth" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_auth finding")
	}
}

func TestEtcdWithAuth(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "bitnami/etcd:3.5",
		Environment: []string{
			"ETCD_ROOT_PASSWORD=securepass",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_auth" {
				t.Error("should not flag missing_auth when root password is set")
			}
		}
	}
}

func TestEtcdExposedPort(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
		Ports: []compose.PortMapping{
			{HostPort: 2379, TargetPort: 2379, Raw: "2379:2379"},
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_port finding")
	}
}

func TestEtcdLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
		Ports: []compose.PortMapping{
			{HostPort: 2379, TargetPort: 2379, Raw: "127.0.0.1:2379:2379", HostIP: "127.0.0.1"},
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				t.Error("should not flag port bound to localhost")
			}
		}
	}
}

func TestEtcdPeerPort(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
		Ports: []compose.PortMapping{
			{HostPort: 2380, TargetPort: 2380, Raw: "2380:2380"},
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_port for peer port 2380")
	}
}

func TestEtcdDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "bitnami/etcd:3.5",
		Environment: []string{
			"ETCD_ROOT_PASSWORD=root:root",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_credentials finding")
	}
}

func TestEtcdInsecureTransport(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
		Environment: []string{
			"ETCD_ADVERTISE_CLIENT_URLS=http://etcd:2379",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "insecure_transport" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected insecure_transport finding")
	}
}

func TestNonEtcdService(t *testing.T) {
	svc := compose.Service{
		Name:  "redis",
		Image: "redis:7",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-etcd service should have no findings")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
		Ports: []compose.PortMapping{
			{HostPort: 2379, TargetPort: 2379, Raw: "2379:2379"},
		},
		Environment: []string{
			"ETCD_ADVERTISE_CLIENT_URLS=http://etcd:2379",
		},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingClientTLS != 1 {
		t.Errorf("expected 1 missing client tls, got %d", r.Summary.MissingClientTLS)
	}
	if r.Summary.MissingAuth != 1 {
		t.Errorf("expected 1 missing auth, got %d", r.Summary.MissingAuth)
	}
	if r.Summary.ExposedPorts != 1 {
		t.Errorf("expected 1 exposed port, got %d", r.Summary.ExposedPorts)
	}
	if r.Summary.InsecureTransport != 1 {
		t.Errorf("expected 1 insecure transport, got %d", r.Summary.InsecureTransport)
	}
}

func TestFormatTextOutput(t *testing.T) {
	svc := compose.Service{
		Name:  "etcd",
		Image: "quay.io/coreos/etcd:v3.5",
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "etcd Security Audit") {
		t.Error("expected header in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Error("expected zero findings in empty report")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}

func TestIsEtcdImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"quay.io/coreos/etcd:v3.5", true},
		{"bitnami/etcd:3.5", true},
		{"k8s.gcr.io/etcd:3.5.0", true},
		{"registry.k8s.io/etcd:3.5.9", true},
		{"nginx:latest", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isEtcdImage(tt.image); got != tt.want {
			t.Errorf("isEtcdImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestMultipleEtcdServices(t *testing.T) {
	svc1 := compose.Service{
		Name:  "etcd1",
		Image: "quay.io/coreos/etcd:v3.5",
	}
	svc2 := compose.Service{
		Name:  "etcd2",
		Image: "bitnami/etcd:3.5",
		Environment: []string{
			"ETCD_CERT_FILE=/certs/server.crt",
			"ETCD_KEY_FILE=/certs/server.key",
			"ETCD_PEER_CERT_FILE=/certs/peer.crt",
			"ETCD_PEER_KEY_FILE=/certs/peer.key",
			"ETCD_ROOT_PASSWORD=securepass",
		},
	}
	r := Analyze(makeCollected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingClientTLS != 1 {
		t.Errorf("expected 1 missing client tls (only svc1), got %d", r.Summary.MissingClientTLS)
	}
}
