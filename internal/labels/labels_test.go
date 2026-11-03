package labels

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestAnalyze_NoLabels(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithLabels != 0 {
		t.Fatalf("expected 0 with labels, got %d", r.Summary.WithLabels)
	}
	if r.Services[0].Grade != "A" {
		t.Fatalf("expected grade A, got %s", r.Services[0].Grade)
	}
}

func TestAnalyze_TraefikLabel(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "proxy",
		Labels: map[string]string{
			"traefik.http.routers.myapp.rule": "Host(`example.com`)",
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "infrastructure_label" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected infrastructure_label finding for Traefik label")
	}
}

func TestAnalyze_WatchtowerAutoUpdate(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"com.centurylinklabs.watchtower.enable": "true",
		},
	})
	r := Analyze(c)
	foundInfra := false
	foundAutoUpdate := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "infrastructure_label" {
			foundInfra = true
		}
		if f.Category == "auto_update_enabled" {
			foundAutoUpdate = true
		}
	}
	if !foundInfra {
		t.Fatal("expected infrastructure_label finding for watchtower")
	}
	if !foundAutoUpdate {
		t.Fatal("expected auto_update_enabled finding")
	}
}

func TestAnalyze_WatchtowerDisabled(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"com.centurylinklabs.watchtower.enable": "false",
		},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "auto_update_enabled" {
			t.Fatal("watchtower disabled should not trigger auto_update finding")
		}
	}
}

func TestAnalyze_InsecureTraefikEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"traefik.http.routers.myapp.entrypoints": "web",
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "insecure_routing" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected insecure_routing finding for HTTP-only entrypoint")
	}
}

func TestAnalyze_SecureTraefikEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"traefik.http.routers.myapp.entrypoints": "websecure",
		},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "insecure_routing" {
			t.Fatal("websecure entrypoint should not trigger insecure_routing")
		}
	}
}

func TestAnalyze_SensitiveLabelValue(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"app.config": "aB3$xY9!kL2mN4pQ",
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "sensitive_label_value" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected sensitive_label_value for high-entropy string")
	}
}

func TestAnalyze_NormalLabelValueNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"app.version": "1.2.3",
			"app.name":    "myapp",
		},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "sensitive_label_value" {
			t.Fatal("normal label values should not be flagged")
		}
	}
}

func TestAnalyze_ScoreFloor(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"traefik.http.routers.a.rule":            "Host(`a.com`)",
			"traefik.http.routers.b.rule":            "Host(`b.com`)",
			"traefik.http.routers.c.rule":            "Host(`c.com`)",
			"traefik.http.services.a.port":           "80",
			"traefik.http.services.b.port":           "81",
			"traefik.http.middlewares.a.headers":      "X-Frame",
			"traefik.http.routers.a.entrypoints":     "web",
			"traefik.http.routers.b.entrypoints":     "web",
			"traefik.http.routers.c.entrypoints":     "web",
			"com.centurylinklabs.watchtower.enable":   "true",
			"secret.val": "aB3$xY9!kL2mN4pQ",
		},
	})
	r := Analyze(c)
	if r.Services[0].Score < 0 {
		t.Fatalf("score should not go below 0, got %d", r.Services[0].Score)
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"},
		{79, "C"}, {70, "C"}, {69, "D"}, {60, "D"},
		{59, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		if g := scoreToGrade(tt.score); g != tt.grade {
			t.Errorf("scoreToGrade(%d) = %s, want %s", tt.score, g, tt.grade)
		}
	}
}

func TestFormatText(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		Labels: map[string]string{
			"traefik.http.routers.myapp.rule": "Host(`example.com`)",
		},
	})
	r := Analyze(c)
	out := FormatText(r)
	if !strings.Contains(out, "Label Security Audit") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(out, "app") {
		t.Fatal("expected service name in text output")
	}
}

func TestAnalyze_MultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "clean"},
		compose.Service{
			Name: "labeled",
			Labels: map[string]string{
				"traefik.http.routers.x.rule": "Host(`x.com`)",
			},
		},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithLabels != 1 {
		t.Fatalf("expected 1 with labels, got %d", r.Summary.WithLabels)
	}
}

func TestAnalyze_CaddyLabel(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Labels: map[string]string{
			"caddy": "example.com",
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "infrastructure_label" && strings.Contains(f.Detail, "Caddy") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected infrastructure_label for Caddy label")
	}
}
