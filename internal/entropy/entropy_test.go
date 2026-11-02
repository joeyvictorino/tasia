package entropy

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestShannonEmpty(t *testing.T) {
	if got := Shannon(""); got != 0 {
		t.Errorf("Shannon('') = %f, want 0", got)
	}
}

func TestShannonUniform(t *testing.T) {
	ent := Shannon("abcdefghijklmnop")
	if ent < 3.5 {
		t.Errorf("Shannon(16 unique chars) = %f, want >= 3.5", ent)
	}
}

func TestShannonRepetitive(t *testing.T) {
	ent := Shannon("aaaaaaaaaa")
	if ent != 0 {
		t.Errorf("Shannon('aaaaaaaaaa') = %f, want 0", ent)
	}
}

func TestShannonKnownValue(t *testing.T) {
	ent := Shannon("ab")
	if ent != 1.0 {
		t.Errorf("Shannon('ab') = %f, want 1.0", ent)
	}
}

func TestAnalyzeHighEntropy(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "api",
						EnvLine:     10,
						Environment: []string{"SECRET_KEY=aB3xZ9qW4rT7mN2pK5vJ8cF1gH6dL0y"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	if len(r.Findings) == 0 {
		t.Fatal("expected at least one finding for high-entropy secret")
	}
	f := r.Findings[0]
	if f.Key != "SECRET_KEY" {
		t.Errorf("key = %q, want SECRET_KEY", f.Key)
	}
	if f.Service != "api" {
		t.Errorf("service = %q, want api", f.Service)
	}
	if f.Entropy < DefaultThreshold {
		t.Errorf("entropy = %f, want >= %f", f.Entropy, DefaultThreshold)
	}
}

func TestAnalyzeSafeKeyDatabase(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "web",
						Environment: []string{"DATABASE_URL=postgres://localhost:5432/mydb"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	for _, f := range r.Findings {
		if f.Key == "DATABASE_URL" {
			t.Error("DATABASE_URL should not be flagged (safe key prefix)")
		}
	}
}

func TestAnalyzeSafeKey(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "app",
						Environment: []string{"LOG_LEVEL=aB3xZ9qW4rT7mN2p"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	if len(r.Findings) != 0 {
		t.Errorf("LOG_LEVEL should be safe; got %d findings", len(r.Findings))
	}
}

func TestAnalyzeSafeValue(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "app",
						Environment: []string{"MY_SETTING=production"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	if len(r.Findings) != 0 {
		t.Errorf("'production' should be safe; got %d findings", len(r.Findings))
	}
}

func TestAnalyzeShortValue(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "app",
						Environment: []string{"X=abc"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	if len(r.Findings) != 0 {
		t.Errorf("short value should be skipped; got %d findings", len(r.Findings))
	}
}

func TestAnalyzeSecretPattern(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "api",
						Environment: []string{"OPENAI_API_KEY=sk-proj-aB3xZ9qW4rT7mN2pK5vJ8cF1gH6dL0y"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	if len(r.Findings) == 0 {
		t.Fatal("expected finding for sk- pattern")
	}
	if r.Findings[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", r.Findings[0].Severity)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{}, DefaultThreshold)
	if len(r.Findings) != 0 {
		t.Errorf("expected no findings for empty collected")
	}
	if r.Summary.TotalEnvVars != 0 {
		t.Errorf("total_env_vars = %d, want 0", r.Summary.TotalEnvVars)
	}
}

func TestSummaryByService(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "svc-a",
						Environment: []string{"TOKEN_A=aB3xZ9qW4rT7mN2pK5vJ8cF1gH6dL0y"},
					},
					{
						Name:        "svc-b",
						Environment: []string{"TOKEN_B=qW4rT7mN2pK5vJ8cF1gH6dL0yaB3xZ9"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	if r.Summary.ByService["svc-a"] < 1 || r.Summary.ByService["svc-b"] < 1 {
		t.Error("expected findings in both services")
	}
}

func TestFormatTextOutput(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "api",
						Environment: []string{"MY_SECRET=aB3xZ9qW4rT7mN2pK5vJ8cF1gH6dL0y"},
					},
				},
			},
		},
	}
	r := Analyze(col, DefaultThreshold)
	text := FormatText(r)
	if !strings.Contains(text, "Entropy Analysis") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "MY_SECRET") {
		t.Error("missing key name")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{}, DefaultThreshold)
	text := FormatText(r)
	if !strings.Contains(text, "No high-entropy") {
		t.Error("missing empty message")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	got := truncate("a-very-long-string", 10)
	if len(got) != 10 {
		t.Errorf("truncate long len = %d, want 10", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncate long = %q, want suffix '...'", got)
	}
}

func TestSortByEntropy(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name: "svc",
						Environment: []string{
							"LOW_ENT=aabbccddee",
							"HIGH_ENT=aB3xZ9qW4rT7mN2pK5vJ8cF1gH6dL0yaB3xZ9qW4rT7",
						},
					},
				},
			},
		},
	}
	r := Analyze(col, 1.0)
	if len(r.Findings) < 2 {
		t.Skipf("need 2+ findings, got %d", len(r.Findings))
	}
	if r.Findings[0].Entropy < r.Findings[1].Entropy {
		t.Error("findings should be sorted by entropy descending")
	}
}
