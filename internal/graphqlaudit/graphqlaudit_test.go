package graphqlaudit

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
	return func(s *compose.Service) {
		s.Environment = append(s.Environment, envs...)
	}
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Image = img
	}
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

func countRule(results []ServiceResult, ruleID string) int {
	n := 0
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule == ruleID {
				n++
			}
		}
	}
	return n
}

func TestIntrospectionEnabled(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_INTROSPECTION=true")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-001") == nil {
		t.Fatal("expected GRAPHQL-001 for introspection enabled")
	}
}

func TestIntrospectionDisabled(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_INTROSPECTION=false")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-001") != nil {
		t.Fatal("unexpected GRAPHQL-001 for introspection disabled")
	}
}

func TestNoDepthLimit(t *testing.T) {
	c := mkCollected(svc("api", withImage("apollo-server"), withEnv("NODE_ENV=production")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-002") == nil {
		t.Fatal("expected GRAPHQL-002 for missing depth limit")
	}
}

func TestDepthLimitSet(t *testing.T) {
	c := mkCollected(svc("api", withImage("apollo-server"), withEnv("GRAPHQL_DEPTH_LIMIT=10")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-002") != nil {
		t.Fatal("unexpected GRAPHQL-002 when depth limit is set")
	}
}

func TestNoComplexityLimit(t *testing.T) {
	c := mkCollected(svc("api", withImage("hasura/graphql-engine"), withEnv("NODE_ENV=production")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-003") == nil {
		t.Fatal("expected GRAPHQL-003 for missing complexity limit")
	}
}

func TestComplexityLimitSet(t *testing.T) {
	c := mkCollected(svc("api", withImage("hasura/graphql-engine"), withEnv("GRAPHQL_COMPLEXITY_LIMIT=1000")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-003") != nil {
		t.Fatal("unexpected GRAPHQL-003 when complexity limit is set")
	}
}

func TestDebugModeEnabled(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_DEBUG=true")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-004") == nil {
		t.Fatal("expected GRAPHQL-004 for debug mode")
	}
}

func TestPlaygroundEnabled(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_PLAYGROUND=true")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-004") == nil {
		t.Fatal("expected GRAPHQL-004 for playground")
	}
}

func TestNoRateLimit(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-api"), withEnv("NODE_ENV=production")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-005") == nil {
		t.Fatal("expected GRAPHQL-005 for missing rate limit")
	}
}

func TestRateLimitSet(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-api"), withEnv("GRAPHQL_RATE_LIMIT=100")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-005") != nil {
		t.Fatal("unexpected GRAPHQL-005 when rate limit is set")
	}
}

func TestBatchNoLimit(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_BATCH=true")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-006") == nil {
		t.Fatal("expected GRAPHQL-006 for batch without limit")
	}
}

func TestBatchWithLimit(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_BATCH=true", "GRAPHQL_BATCH_LIMIT=10")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-006") != nil {
		t.Fatal("unexpected GRAPHQL-006 when batch limit is set")
	}
}

func TestNonGraphQLServiceIgnored(t *testing.T) {
	c := mkCollected(svc("postgres", withImage("postgres:15")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for non-GraphQL service, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryAffectedCount(t *testing.T) {
	c := mkCollected(
		svc("api", withImage("graphql-server"), withEnv("GRAPHQL_INTROSPECTION=true")),
		svc("db", withImage("postgres:15")),
	)
	r := Analyze(c)
	if r.Summary.AffectedServices != 1 {
		t.Fatalf("expected 1 affected, got %d", r.Summary.AffectedServices)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_INTROSPECTION=true")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "GraphQL Security") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server")))
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "Results") {
		t.Fatal("expected Results in JSON")
	}
}

func TestMultipleRulesOnOneService(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("GRAPHQL_INTROSPECTION=true", "GRAPHQL_DEBUG=true", "GRAPHQL_BATCH=true")))
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestHasuraDetected(t *testing.T) {
	c := mkCollected(svc("hasura", withImage("hasura/graphql-engine:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for hasura service")
	}
}

func TestEnableIntrospectionVariant(t *testing.T) {
	c := mkCollected(svc("api", withImage("graphql-server"), withEnv("ENABLE_INTROSPECTION=1")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-001") == nil {
		t.Fatal("expected GRAPHQL-001 for ENABLE_INTROSPECTION=1")
	}
}

func TestMaxQueryDepthAlternative(t *testing.T) {
	c := mkCollected(svc("api", withImage("apollo-server"), withEnv("MAX_QUERY_DEPTH=15")))
	r := Analyze(c)
	if findRule(r.Results, "GRAPHQL-002") != nil {
		t.Fatal("unexpected GRAPHQL-002 when MAX_QUERY_DEPTH is set")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := mkCollected()
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}
