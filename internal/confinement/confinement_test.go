package confinement

import (
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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestMinimalService(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Services[0].Score >= 50 {
		t.Errorf("expected weak score for minimal service, got %d", r.Services[0].Score)
	}
	if !hasRule(r.Services[0], "confinement_weak") {
		t.Error("expected confinement_weak for minimal service")
	}
}

func TestPrivilegedService(t *testing.T) {
	c := collected(compose.Service{Name: "web", Privileged: true})
	r := Analyze(c)
	if r.Services[0].Score > 15 {
		t.Errorf("expected low score for privileged service, got %d", r.Services[0].Score)
	}
}

func TestCapDropAll(t *testing.T) {
	c := collected(compose.Service{Name: "web", CapDrop: []string{"ALL"}})
	r := Analyze(c)
	if r.Services[0].Score < 15 {
		t.Errorf("expected cap_drop ALL to add 15 points, got %d", r.Services[0].Score)
	}
}

func TestSeccomp(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		SecurityOpt: []string{"seccomp=default.json"},
	})
	r := Analyze(c)
	if r.Services[0].Score < 15 {
		t.Errorf("expected seccomp to add points, got %d", r.Services[0].Score)
	}
}

func TestHostNetwork(t *testing.T) {
	c := collected(compose.Service{Name: "web", NetworkMode: "host"})
	r := Analyze(c)
	if r.Services[0].Score >= 50 {
		t.Errorf("expected host network to reduce score, got %d", r.Services[0].Score)
	}
}

func TestReadOnlyRootfs(t *testing.T) {
	c := collected(compose.Service{
		Name:     "web",
		ReadOnly: true,
	})
	r := Analyze(c)
	if r.Services[0].Score < 15 {
		t.Errorf("expected read_only to add 15 points, got %d", r.Services[0].Score)
	}
}

func TestModerateConfinement(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"seccomp=default.json"},
	})
	r := Analyze(c)
	if r.Services[0].Score < 50 || r.Services[0].Score >= 75 {
		t.Errorf("expected moderate score (50-74), got %d", r.Services[0].Score)
	}
	if !hasRule(r.Services[0], "confinement_moderate") {
		t.Error("expected confinement_moderate finding")
	}
}

func TestWellHardenedService(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"seccomp=default.json"},
		ReadOnly:    true,
		UsernsMode:  "private",
		MemLimit:    "512m",
	})
	r := Analyze(c)
	if r.Services[0].Score < 75 {
		t.Errorf("expected high score for well-hardened service, got %d", r.Services[0].Score)
	}
	if hasRule(r.Services[0], "confinement_weak") || hasRule(r.Services[0], "confinement_moderate") {
		t.Error("should have no confinement findings for well-hardened service")
	}
}

func TestSummaryWeakCount(t *testing.T) {
	c := collected(
		compose.Service{Name: "web"},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	if r.Summary.WeakServices != 2 {
		t.Errorf("expected 2 weak services, got %d", r.Summary.WeakServices)
	}
}
