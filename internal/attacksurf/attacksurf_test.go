package attacksurf

import (
	"math"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{100, "F"},
		{75, "F"},
		{74.9, "D"},
		{60, "D"},
		{59.9, "C"},
		{45, "C"},
		{44.9, "B"},
		{30, "B"},
		{29.9, "B+"},
		{15, "B+"},
		{14.9, "A"},
		{0, "A"},
	}
	for _, tt := range tests {
		got := gradeFromScore(tt.score)
		if got != tt.want {
			t.Errorf("gradeFromScore(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestScoreNetworkHostMode(t *testing.T) {
	svc := &compose.Service{NetworkMode: "host"}
	d := scoreNetwork(svc)
	if d.Score < 20 {
		t.Errorf("host network mode should score at least 20, got %.1f", d.Score)
	}
	if d.Name != "network_exposure" {
		t.Errorf("dimension name = %q, want %q", d.Name, "network_exposure")
	}
}

func TestScoreNetworkPorts(t *testing.T) {
	svc := &compose.Service{
		Ports: []compose.PortMapping{
			{HostPort: 80, HostIP: "0.0.0.0"},
			{HostPort: 443, HostIP: "127.0.0.1"},
		},
	}
	d := scoreNetwork(svc)
	if d.Score != 4 {
		t.Errorf("expected score 4 (3+1), got %.1f", d.Score)
	}
}

func TestScoreNetworkDNS(t *testing.T) {
	svc := &compose.Service{DNS: []string{"8.8.8.8"}}
	d := scoreNetwork(svc)
	if d.Score != 2 {
		t.Errorf("custom DNS should add 2, got %.1f", d.Score)
	}
}

func TestScoreNetworkCapped(t *testing.T) {
	svc := &compose.Service{
		NetworkMode: "host",
		Ports: []compose.PortMapping{
			{HostPort: 80},
			{HostPort: 443},
			{HostPort: 8080},
		},
		DNS: []string{"8.8.8.8"},
	}
	d := scoreNetwork(svc)
	if d.Score > 25 {
		t.Errorf("network score should cap at 25, got %.1f", d.Score)
	}
}

func TestScorePrivilegedMode(t *testing.T) {
	svc := &compose.Service{Privileged: true}
	d := scorePrivilege(svc)
	if d.Score != 25 {
		t.Errorf("privileged mode should score 25, got %.1f", d.Score)
	}
}

func TestScorePrivilegeCaps(t *testing.T) {
	svc := &compose.Service{
		CapAdd: []string{"SYS_ADMIN", "NET_RAW"},
	}
	d := scorePrivilege(svc)
	// SYS_ADMIN=15 + NET_RAW=6 + no-drop-all=5 = 26, capped at 25
	if d.Score != 25 {
		t.Errorf("expected capped score 25, got %.1f", d.Score)
	}
}

func TestScorePrivilegeCapDropAll(t *testing.T) {
	svc := &compose.Service{
		CapAdd:  []string{"NET_RAW"},
		CapDrop: []string{"ALL"},
	}
	d := scorePrivilege(svc)
	// NET_RAW=6, no penalty for missing drop-all
	if d.Score != 6 {
		t.Errorf("expected score 6, got %.1f", d.Score)
	}
}

func TestScoreDataAccessDockerSocket(t *testing.T) {
	svc := &compose.Service{
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	}
	d := scoreDataAccess(svc)
	if d.Score < 15 {
		t.Errorf("docker socket mount should score at least 15, got %.1f", d.Score)
	}
}

func TestScoreDataAccessRootFS(t *testing.T) {
	svc := &compose.Service{
		Volumes: []string{"/:/host"},
	}
	d := scoreDataAccess(svc)
	if d.Score < 12 {
		t.Errorf("root filesystem mount should score at least 12, got %.1f", d.Score)
	}
}

func TestScoreDataAccessSensitiveEnv(t *testing.T) {
	svc := &compose.Service{
		Environment: []string{"DB_PASSWORD=secret123"},
	}
	d := scoreDataAccess(svc)
	if d.Score < 3 {
		t.Errorf("sensitive env var should add at least 3, got %.1f", d.Score)
	}
}

func TestScoreDataAccessReadOnly(t *testing.T) {
	svc := &compose.Service{
		Volumes: []string{"/etc/config:/config:ro"},
	}
	d := scoreDataAccess(svc)
	if d.Score != 3 {
		t.Errorf("sensitive RO mount should score 3, got %.1f", d.Score)
	}
}

func TestScoreIsolation(t *testing.T) {
	svc := &compose.Service{
		PidMode:   "host",
		IpcMode:   "host",
		UsernsMode: "host",
		ReadOnly:  false,
	}
	d := scoreIsolation(svc)
	// pid=5 + ipc=4 + userns=4 + non-readonly=2 = 15
	if d.Score != 15 {
		t.Errorf("full isolation issues should score 15, got %.1f", d.Score)
	}
}

func TestScoreIsolationReadOnly(t *testing.T) {
	svc := &compose.Service{ReadOnly: true}
	d := scoreIsolation(svc)
	if d.Score != 0 {
		t.Errorf("read-only container with no sharing should score 0, got %.1f", d.Score)
	}
}

func TestScoreConfiguration(t *testing.T) {
	svc := &compose.Service{
		OomKillDisable: true,
	}
	d := scoreConfiguration(svc)
	// no mem_limit=3 + no healthcheck=2 + no restart=1 + no security_opt=2 + oom_kill_disable=2 = 10
	if d.Score != 10 {
		t.Errorf("expected score 10, got %.1f", d.Score)
	}
}

func TestScoreConfigurationWellConfigured(t *testing.T) {
	svc := &compose.Service{
		MemLimit:    "512m",
		Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}},
		Restart:     "unless-stopped",
		SecurityOpt: []string{"no-new-privileges"},
	}
	d := scoreConfiguration(svc)
	if d.Score != 0 {
		t.Errorf("well-configured service should score 0, got %.1f", d.Score)
	}
}

func TestScoreService(t *testing.T) {
	svc := &compose.Service{
		Name:       "test-svc",
		Privileged: true,
	}
	ss := scoreService(svc, "docker-compose.yml")
	if ss.Name != "test-svc" {
		t.Errorf("service name = %q, want %q", ss.Name, "test-svc")
	}
	if ss.File != "docker-compose.yml" {
		t.Errorf("file = %q, want %q", ss.File, "docker-compose.yml")
	}
	if len(ss.Dimensions) != 5 {
		t.Errorf("expected 5 dimensions, got %d", len(ss.Dimensions))
	}
	if ss.Total <= 0 {
		t.Errorf("total should be > 0 for privileged service, got %.1f", ss.Total)
	}
	if ss.Total > 100 {
		t.Errorf("total should cap at 100, got %.1f", ss.Total)
	}
}

func TestAnalyze(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Privileged: true},
					{Name: "db", MemLimit: "256m", Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}, Restart: "always", SecurityOpt: []string{"no-new-privileges"}, ReadOnly: true},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.TotalServices != 2 {
		t.Errorf("total services = %d, want 2", r.Summary.TotalServices)
	}
	if len(r.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(r.Services))
	}
	// Services should be sorted descending by total
	if r.Services[0].Total < r.Services[1].Total {
		t.Error("services should be sorted descending by total score")
	}
	if r.Summary.OverallGrade == "" {
		t.Error("overall grade should not be empty")
	}
	if math.IsNaN(r.Summary.OverallScore) {
		t.Error("overall score should not be NaN")
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Errorf("empty input should have 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.OverallScore != 0 {
		t.Errorf("empty input should have 0 score, got %.1f", r.Summary.OverallScore)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Services: []ServiceScore{
			{
				Name: "web", File: "compose.yml", Total: 55, Grade: "D",
				Dimensions: []DimensionScore{
					{Name: "network_exposure", Score: 10, Max: 25, Notes: []string{"port 80 bound to all interfaces"}},
					{Name: "privilege_level", Score: 25, Max: 25},
					{Name: "data_access", Score: 5, Max: 25},
					{Name: "isolation", Score: 10, Max: 15},
					{Name: "configuration", Score: 5, Max: 10},
				},
			},
		},
		Summary: Summary{TotalServices: 1, OverallScore: 55, OverallGrade: "D", High: 1},
	}

	text := FormatText(r)
	if !strings.Contains(text, "Attack Surface Analysis") {
		t.Error("output should contain header")
	}
	if !strings.Contains(text, "web") {
		t.Error("output should contain service name")
	}
	if !strings.Contains(text, "port 80") {
		t.Error("output should contain notes")
	}
	if !strings.Contains(text, "55.0/100") {
		t.Error("output should contain total score")
	}
}

func TestSummaryCounts(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "test.yml",
				Services: []compose.Service{
					{Name: "critical", Privileged: true, NetworkMode: "host", PidMode: "host", IpcMode: "host", UsernsMode: "host"},
					{Name: "low", MemLimit: "512m", Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}, Restart: "always", SecurityOpt: []string{"no-new-privileges"}, ReadOnly: true},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.Critical+r.Summary.High+r.Summary.Medium+r.Summary.Low != 2 {
		t.Errorf("sum of severity counts should equal total services (2), got %d",
			r.Summary.Critical+r.Summary.High+r.Summary.Medium+r.Summary.Low)
	}
}
