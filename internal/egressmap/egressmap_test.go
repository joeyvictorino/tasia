package egressmap

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalRoutes != 0 {
		t.Fatalf("expected 0 routes, got %d", r.Summary.TotalRoutes)
	}
	if r.Summary.Score != 100 {
		t.Fatalf("expected score 100, got %d", r.Summary.Score)
	}
}

func TestPortRoutes(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name: "app",
				Ports: []compose.PortMapping{
					{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080"},
				},
			}},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalRoutes != 1 {
		t.Fatalf("expected 1 route, got %d", r.Summary.TotalRoutes)
	}
	if r.Routes[0].Source != "ports" {
		t.Fatalf("expected source 'ports', got %q", r.Routes[0].Source)
	}
}

func TestHighRiskPort(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name: "db",
				Ports: []compose.PortMapping{
					{HostPort: 5432, TargetPort: 5432, Raw: "5432:5432"},
				},
			}},
		}},
	}
	r := Analyze(c)
	if r.Routes[0].Risk != "high" {
		t.Fatalf("expected high risk for postgres port, got %q", r.Routes[0].Risk)
	}
}

func TestEnvRoutes(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "worker",
				Environment: []string{"DATABASE_URL=postgres://user:pass@db.example.com:5432/app"},
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, route := range r.Routes {
		if route.Destination == "db.example.com" {
			found = true
			if route.Protocol != "postgres" {
				t.Fatalf("expected postgres protocol, got %q", route.Protocol)
			}
		}
	}
	if !found {
		t.Fatal("expected route to db.example.com")
	}
}

func TestNetworkModeHost(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "agent",
				NetworkMode: "host",
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, route := range r.Routes {
		if route.Source == "network_mode:host" && route.Risk == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected high-risk network_mode:host route")
	}
}

func TestWebhookHighRisk(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "notifier",
				Environment: []string{"WEBHOOK_URL=https://hooks.slack.com/services/xxx"},
			}},
		}},
	}
	r := Analyze(c)
	if len(r.Routes) == 0 {
		t.Fatal("expected at least one route")
	}
	if r.Routes[0].Risk != "high" {
		t.Fatalf("expected high risk for webhook, got %q", r.Routes[0].Risk)
	}
}

func TestLocalHostNotExternal(t *testing.T) {
	if isExternalHost("localhost") {
		t.Fatal("localhost should not be external")
	}
	if isExternalHost("127.0.0.1") {
		t.Fatal("127.0.0.1 should not be external")
	}
}

func TestExternalHost(t *testing.T) {
	if !isExternalHost("api.openai.com") {
		t.Fatal("api.openai.com should be external")
	}
}

func TestGuessProtocol(t *testing.T) {
	cases := map[string]string{
		"https://example.com":           "https",
		"http://example.com":            "http",
		"redis://cache:6379":            "redis",
		"mongodb://db:27017/test":       "mongodb",
		"amqp://mq:5672":               "amqp",
		"postgres://localhost:5432/test": "postgres",
	}
	for input, want := range cases {
		got := guessProtocol(input)
		if got != want {
			t.Errorf("guessProtocol(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(&collect.Collected{})
	out := FormatText(r)
	if !strings.Contains(out, "Egress Route Map") {
		t.Fatal("expected header")
	}
}

func TestScoreGrade(t *testing.T) {
	if scoreGrade(95) != "A" {
		t.Fatal("expected A")
	}
	if scoreGrade(50) != "F" {
		t.Fatal("expected F")
	}
}
