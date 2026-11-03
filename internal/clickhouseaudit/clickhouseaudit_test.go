package clickhouseaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func coll(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{{Services: services}},
	}
}

func TestIsClickhouseImage(t *testing.T) {
	tests := []struct {
		img  string
		want bool
	}{
		{"clickhouse/clickhouse-server:latest", true},
		{"yandex/clickhouse-server:21.8", true},
		{"bitnami/clickhouse:latest", true},
		{"CLICKHOUSE/CLICKHOUSE-SERVER", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, tc := range tests {
		if got := isClickhouseImage(tc.img); got != tc.want {
			t.Errorf("isClickhouseImage(%q) = %v, want %v", tc.img, got, tc.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	svc := compose.Service{
		Name:  "ch",
		Image: "clickhouse/clickhouse-server",
	}
	sr := analyzeService(svc)
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "clickhouse_no_auth" {
			found = true
		}
	}
	if !found {
		t.Error("expected no auth finding")
	}
}

func TestAuthConfigured(t *testing.T) {
	svc := compose.Service{
		Name:        "ch",
		Image:       "clickhouse/clickhouse-server",
		Environment: []string{"CLICKHOUSE_PASSWORD=str0ngP@ss!"},
	}
	sr := analyzeService(svc)
	for _, f := range sr.Findings {
		if f.Rule == "clickhouse_no_auth" {
			t.Error("should not trigger no auth when password set")
		}
	}
}

func TestDefaultPassword(t *testing.T) {
	tests := []string{"CLICKHOUSE_PASSWORD=default", "CLICKHOUSE_PASSWORD=", "CLICKHOUSE_PASSWORD=clickhouse"}
	for _, env := range tests {
		if !hasDefaultPassword([]string{env}) {
			t.Errorf("expected default password for %s", env)
		}
	}
}

func TestStrongPassword(t *testing.T) {
	if hasDefaultPassword([]string{"CLICKHOUSE_PASSWORD=V3ryStr0ng!Pass"}) {
		t.Error("strong password should not trigger")
	}
}

func TestNoTLS(t *testing.T) {
	if !hasNoTLS([]string{"CLICKHOUSE_SSL=false"}) {
		t.Error("expected no TLS detected")
	}
}

func TestDebugEnabled(t *testing.T) {
	if !hasDebugEnabled([]string{"CLICKHOUSE_LOG_LEVEL=trace"}) {
		t.Error("expected debug detected")
	}
	if !hasDebugEnabled([]string{"CLICKHOUSE_LOG_LEVEL=debug"}) {
		t.Error("expected debug detected")
	}
}

func TestExposedHTTPPort(t *testing.T) {
	svc := compose.Service{
		Name:  "ch",
		Image: "clickhouse/clickhouse-server",
		Ports: []compose.PortMapping{{HostPort: 8123, TargetPort: 8123, HostIP: ""}},
	}
	sr := analyzeService(svc)
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "clickhouse_exposed_port" && strings.Contains(f.Message, "8123") {
			found = true
		}
	}
	if !found {
		t.Error("expected exposed HTTP port finding")
	}
}

func TestExposedNativePort(t *testing.T) {
	svc := compose.Service{
		Name:  "ch",
		Image: "clickhouse/clickhouse-server",
		Ports: []compose.PortMapping{{HostPort: 9000, TargetPort: 9000, HostIP: ""}},
	}
	sr := analyzeService(svc)
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "clickhouse_exposed_port" {
			found = true
		}
	}
	if !found {
		t.Error("expected exposed native port finding")
	}
}

func TestLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name:  "ch",
		Image: "clickhouse/clickhouse-server",
		Ports: []compose.PortMapping{{HostPort: 8123, TargetPort: 8123, HostIP: "127.0.0.1"}},
	}
	sr := analyzeService(svc)
	for _, f := range sr.Findings {
		if f.Rule == "clickhouse_exposed_port" {
			t.Error("localhost-bound port should not trigger")
		}
	}
}

func TestCleanService(t *testing.T) {
	svc := compose.Service{
		Name:        "ch",
		Image:       "clickhouse/clickhouse-server",
		Environment: []string{"CLICKHOUSE_PASSWORD=str0ngP@ss!"},
	}
	sr := analyzeService(svc)
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings for clean service, got %d", len(sr.Findings))
	}
}

func TestSkipsNonClickhouse(t *testing.T) {
	c := coll(compose.Service{Name: "web", Image: "nginx"})
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("should skip non-clickhouse services")
	}
}

func TestAnalyzeSummary(t *testing.T) {
	c := coll(compose.Service{
		Name:        "ch",
		Image:       "clickhouse/clickhouse-server",
		Environment: []string{"CLICKHOUSE_PASSWORD=default"},
	})
	r := Analyze(c)
	if r.Summary.DefaultPassword < 1 {
		t.Error("expected default password in summary")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Report{Path: "/test"}
	text := FormatText(r)
	if !strings.Contains(text, "No ClickHouse") {
		t.Error("should say no ClickHouse services")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	c := coll(compose.Service{
		Name:  "ch",
		Image: "clickhouse/clickhouse-server",
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "clickhouse_no_auth") {
		t.Error("format should include finding rule")
	}
}
