package readonlyfs

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Services: services},
		},
	}
}

func svc(name string, readOnly bool, volumes []string, tmpfs []string) compose.Service {
	return compose.Service{
		Name:     name,
		ReadOnly: readOnly,
		Volumes:  volumes,
		Tmpfs:    tmpfs,
	}
}

func TestAnalyze_Empty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestAnalyze_ReadOnlyService(t *testing.T) {
	c := makeCollected(svc("web", true, nil, []string{"/tmp"}))
	r := Analyze(c)
	if r.Summary.ReadOnlyCount != 1 {
		t.Fatalf("expected 1 read-only, got %d", r.Summary.ReadOnlyCount)
	}
	if r.Summary.WritableCount != 0 {
		t.Fatalf("expected 0 writable, got %d", r.Summary.WritableCount)
	}
}

func TestAnalyze_WritableService(t *testing.T) {
	c := makeCollected(svc("api", false, nil, nil))
	r := Analyze(c)
	if r.Summary.WritableCount != 1 {
		t.Fatalf("expected 1 writable, got %d", r.Summary.WritableCount)
	}
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "readonly_fs_missing" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected readonly_fs_missing finding")
	}
}

func TestAnalyze_WritableBindMount(t *testing.T) {
	c := makeCollected(svc("db", true, []string{"/data/db:/var/lib/db"}, []string{"/tmp"}))
	r := Analyze(c)
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "readonly_writable_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected readonly_writable_bind finding")
	}
}

func TestAnalyze_ReadOnlyBindMount(t *testing.T) {
	c := makeCollected(svc("cache", true, []string{"/config:/etc/app:ro"}, []string{"/tmp"}))
	r := Analyze(c)
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "readonly_writable_bind" {
				t.Fatal("should not flag read-only bind mount")
			}
		}
	}
}

func TestAnalyze_NoTmpfs(t *testing.T) {
	c := makeCollected(svc("worker", true, nil, nil))
	r := Analyze(c)
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "readonly_no_tmpfs" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected readonly_no_tmpfs finding")
	}
}

func TestAnalyze_Multiple(t *testing.T) {
	c := makeCollected(
		svc("web", true, nil, []string{"/tmp"}),
		svc("api", false, []string{"/app/data:/data"}, nil),
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(svc("web", false, nil, nil))
	r := Analyze(c)
	out := FormatText(r)
	if !strings.Contains(out, "Read-Only Filesystem") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSON(t *testing.T) {
	c := makeCollected(svc("web", true, nil, []string{"/tmp"}))
	r := Analyze(c)
	out := FormatJSON(r)
	if !strings.Contains(out, `"readonly_count"`) {
		t.Fatal("expected readonly_count in JSON")
	}
}

func TestIsWritableBindMount(t *testing.T) {
	cases := []struct {
		vol  string
		want bool
	}{
		{"/host:/container", true},
		{"./local:/container", true},
		{"/host:/container:ro", false},
		{"named-volume:/data", false},
		{"/tmp", false},
	}
	for _, tc := range cases {
		got := isWritableBindMount(tc.vol)
		if got != tc.want {
			t.Errorf("isWritableBindMount(%q) = %v, want %v", tc.vol, got, tc.want)
		}
	}
}
