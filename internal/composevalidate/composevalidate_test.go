package composevalidate

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(files ...compose.File) *collect.Collected {
	return &collect.Collected{ComposeFiles: files}
}

func svc(name, image string) compose.Service {
	return compose.Service{Name: name, Image: image}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(collected())
	if r.Summary.FilesChecked != 0 {
		t.Fatalf("expected 0 files, got %d", r.Summary.FilesChecked)
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(collected(compose.File{Path: "docker-compose.yml"}))
	found := false
	for _, f := range r.Findings {
		if f.Severity == "high" && strings.Contains(f.Message, "no services") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for no services")
	}
}

func TestNoImage(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{{Name: "app"}},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "no image") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for missing image")
	}
}

func TestLatestTag(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "nginx:latest")},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, ":latest") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for :latest tag")
	}
}

func TestNoTag(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "nginx")},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "no tag") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for missing tag")
	}
}

func TestPrivileged(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.0", Privileged: true,
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Severity == "critical" && strings.Contains(f.Message, "privileged") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical finding for privileged")
	}
}

func TestHostNetwork(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.0", NetworkMode: "host",
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "host network") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for host network")
	}
}

func TestSensitiveVolume(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.0",
			Volumes: []string{"/:/mnt"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if f.Severity == "critical" && strings.Contains(f.Message, "sensitive host path") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical finding for root volume mount")
	}
}

func TestInlineSecret(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.0",
			Environment: []string{"DB_PASSWORD=secret123"},
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "inline secret") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for inline secret")
	}
}

func TestNoRestartPolicy(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "nginx:1.0")},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "no restart policy") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for no restart policy")
	}
}

func TestNoResourceLimits(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "nginx:1.0")},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "no resource limits") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for no resource limits")
	}
}

func TestCleanService(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.25",
			Restart: "unless-stopped", MemLimit: "512m", CPUs: "0.5",
			Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80, HostIP: "127.0.0.1"}},
		}},
	}))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for clean service, got %d: %+v", r.Summary.TotalFindings, r.Findings)
	}
}

func TestSeverityOrdering(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:latest",
			Privileged: true, NetworkMode: "host",
			Volumes: []string{"/:/mnt"},
		}},
	}))
	for i := 1; i < len(r.Findings); i++ {
		if sevRank(r.Findings[i].Severity) > sevRank(r.Findings[i-1].Severity) {
			t.Errorf("finding %d (%s) ranked higher than %d (%s)",
				i, r.Findings[i].Severity, i-1, r.Findings[i-1].Severity)
		}
	}
}

func TestPortBoundAllInterfaces(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Image: "nginx:1.0",
			Ports:   []compose.PortMapping{{HostPort: 80, TargetPort: 80}},
			Restart: "always", MemLimit: "1g", CPUs: "1",
		}},
	}))
	found := false
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "all interfaces") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for port bound to all interfaces")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "nginx:1.0")},
	}))
	text := FormatText(r)
	if !strings.Contains(text, "Compose Schema Validation") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(collected())
	text := FormatText(r)
	if !strings.Contains(text, "No compose files found") {
		t.Fatal("expected empty message")
	}
}

func TestSummaryCounts(t *testing.T) {
	r := Analyze(collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{{
			Name: "app", Privileged: true,
		}},
	}))
	if r.Summary.CriticalCount < 1 {
		t.Fatal("expected at least one critical finding")
	}
	total := r.Summary.CriticalCount + r.Summary.HighCount + r.Summary.MediumCount + r.Summary.LowCount
	if total != r.Summary.TotalFindings {
		t.Fatalf("severity counts (%d) don't sum to total (%d)", total, r.Summary.TotalFindings)
	}
}
