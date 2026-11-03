package sidecar

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeNoSidecars(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "myapp:1.0"},
				},
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.SidecarCount != 0 {
		t.Errorf("expected 0 sidecars, got %d", r.Summary.SidecarCount)
	}
}

func TestAnalyzeLoggingSidecar(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "myapp:1.0"},
					{
						Name:      "logger",
						Image:     "fluentd:latest",
						DependsOn: map[string]compose.DependsOnCondition{"web": {}},
					},
				},
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.SidecarCount == 0 {
		t.Error("expected sidecars detected")
	}
}

func TestAnalyzeProxySidecar(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "api", Image: "myapi:1.0"},
					{
						Name:      "proxy",
						Image:     "envoy:1.28",
						DependsOn: map[string]compose.DependsOnCondition{"api": {}},
					},
				},
			},
		},
	}
	r := Analyze(&c)
	found := false
	for _, g := range r.Groups {
		for _, sc := range g.Sidecars {
			if sc.Type == TypeProxy {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected proxy sidecar")
	}
}

func TestPrivilegeEscalation(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Image: "myapp:1.0", Privileged: false},
					{
						Name:       "monitor",
						Image:      "prometheus:latest",
						Privileged: true,
						DependsOn:  map[string]compose.DependsOnCondition{"app": {}},
					},
				},
			},
		},
	}
	r := Analyze(&c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "sidecar_priv_escalation" {
			found = true
		}
	}
	if !found {
		t.Error("expected sidecar_priv_escalation finding")
	}
	if r.Summary.Score >= 100 {
		t.Errorf("expected degraded score, got %d", r.Summary.Score)
	}
}

func TestSharedVolumes(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Image: "myapp:1.0", Volumes: []string{"logs:/var/log"}},
					{
						Name:      "logger",
						Image:     "fluentd:latest",
						Volumes:   []string{"logs:/var/log"},
						DependsOn: map[string]compose.DependsOnCondition{"app": {}},
					},
				},
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.SharedVolumes == 0 {
		t.Error("expected shared volumes detected")
	}
}

func TestClassifyImageLogging(t *testing.T) {
	if ClassifyImage("fluentd:latest") != TypeLogging {
		t.Error("fluentd should be logging")
	}
	if ClassifyImage("fluent-bit:2.0") != TypeLogging {
		t.Error("fluent-bit should be logging")
	}
}

func TestClassifyImageMonitoring(t *testing.T) {
	if ClassifyImage("prometheus:latest") != TypeMonitoring {
		t.Error("prometheus should be monitoring")
	}
	if ClassifyImage("grafana/grafana:9.0") != TypeMonitoring {
		t.Error("grafana should be monitoring")
	}
}

func TestClassifyImageProxy(t *testing.T) {
	if ClassifyImage("envoy:1.28") != TypeProxy {
		t.Error("envoy should be proxy")
	}
	if ClassifyImage("traefik:3.0") != TypeProxy {
		t.Error("traefik should be proxy")
	}
}

func TestClassifyImageCustom(t *testing.T) {
	if ClassifyImage("myapp:1.0") != TypeCustom {
		t.Error("myapp should be custom")
	}
}

func TestNetworkModeSidecar(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Image: "myapp:1.0"},
					{Name: "proxy", Image: "envoy:1.28", NetworkMode: "service:app"},
				},
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.SidecarCount == 0 {
		t.Error("expected network_mode sidecar detection")
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.Score != 100 {
		t.Errorf("expected score 100 for empty, got %d", r.Summary.Score)
	}
}

func TestFormatText(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Image: "myapp:1.0"},
					{Name: "logs", Image: "fluentd:latest", DependsOn: map[string]compose.DependsOnCondition{"app": {}}},
				},
			},
		},
	}
	r := Analyze(&c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	r := Report{
		Summary: Summary{TotalServices: 1, SidecarCount: 2, Score: 90},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Summary.Score != r.Summary.Score {
		t.Error("score mismatch after JSON round-trip")
	}
}
