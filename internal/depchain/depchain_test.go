package depchain

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAgentNoDeps(t *testing.T) {
	c := collected(
		compose.Service{Name: "agent", Image: "langchain-agent:latest"},
		compose.Service{Name: "db", Image: "postgres:15"},
	)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		if sr.Service == "agent" {
			for _, f := range sr.Findings {
				if f.Rule == "dep_chain_missing" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected dep_chain_missing for agent without depends_on")
	}
}

func TestWeakCondition(t *testing.T) {
	c := collected(
		compose.Service{
			Name:  "agent",
			Image: "my-agent:latest",
			DependsOn: map[string]compose.DependsOnCondition{
				"db": {Condition: "service_started"},
			},
		},
		compose.Service{Name: "db", Image: "postgres:15"},
	)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		if sr.Service == "agent" {
			for _, f := range sr.Findings {
				if f.Rule == "dep_chain_weak_condition" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected dep_chain_weak_condition for service_started on postgres")
	}
}

func TestHealthyButNoHealthcheck(t *testing.T) {
	c := collected(
		compose.Service{
			Name:  "agent",
			Image: "my-agent:latest",
			DependsOn: map[string]compose.DependsOnCondition{
				"db": {Condition: "service_healthy"},
			},
		},
		compose.Service{Name: "db", Image: "postgres:15"},
	)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		if sr.Service == "agent" {
			for _, f := range sr.Findings {
				if f.Rule == "dep_chain_no_healthcheck" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected dep_chain_no_healthcheck when dependent has no healthcheck")
	}
}

func TestHealthyWithHealthcheck(t *testing.T) {
	c := collected(
		compose.Service{
			Name:  "agent",
			Image: "my-agent:latest",
			DependsOn: map[string]compose.DependsOnCondition{
				"db": {Condition: "service_healthy"},
			},
		},
		compose.Service{
			Name:        "db",
			Image:       "postgres:15",
			Healthcheck: &compose.Healthcheck{Test: []string{"pg_isready"}},
		},
	)
	r := Analyze(c)
	for _, sr := range r.Services {
		if sr.Service == "agent" {
			for _, f := range sr.Findings {
				if f.Rule == "dep_chain_no_healthcheck" {
					t.Error("should not flag when healthcheck exists")
				}
			}
		}
	}
}

func TestNonAgentNoDeps(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", Image: "nginx:latest"},
	)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "dep_chain_missing" {
				t.Error("non-agent service without deps should not be flagged")
			}
		}
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{
			Name:  "agent",
			Image: "langchain-agent",
			DependsOn: map[string]compose.DependsOnCondition{
				"db": {Condition: "service_started"},
			},
		},
		compose.Service{Name: "db", Image: "postgres:15"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("total services = %d", r.Summary.TotalServices)
	}
	if r.Summary.WeakConditions < 1 {
		t.Error("expected weak conditions")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(
		compose.Service{Name: "agent", Image: "my-agent"},
		compose.Service{Name: "db", Image: "postgres:15"},
	)
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("empty text output")
	}
}

func TestJSON(t *testing.T) {
	c := collected(
		compose.Service{Name: "agent", Image: "langchain-agent"},
		compose.Service{Name: "db", Image: "postgres:15"},
	)
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}
