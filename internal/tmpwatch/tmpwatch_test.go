package tmpwatch

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestTmpHostMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/host/tmp:/tmp"},
	})
	r := Analyze(c)
	if r.Summary.TmpHostMounted == 0 {
		t.Fatal("expected tmp host mounted finding")
	}
}

func TestTmpSharedVolume(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "a", Volumes: []string{"shared:/tmp"}},
					{Name: "b", Volumes: []string{"shared:/var/tmp"}},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TmpSharedVolume == 0 {
		t.Fatal("expected shared volume finding")
	}
}

func TestTmpWritable(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"data:/tmp"},
	})
	r := Analyze(c)
	if r.Summary.TmpWritable == 0 {
		t.Fatal("expected writable tmp finding")
	}
}

func TestTmpNoTmpfs(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "agent",
	})
	r := Analyze(c)
	if r.Summary.TmpNoTmpfs == 0 {
		t.Fatal("expected no tmpfs finding")
	}
}

func TestTmpNoSizeLimit(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:  "agent",
		Tmpfs: []string{"/tmp"},
	})
	r := Analyze(c)
	if r.Summary.TmpNoSizeLimit == 0 {
		t.Fatal("expected no size limit finding")
	}
}

func TestTmpfsSized(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:     "agent",
		Tmpfs:    []string{"/tmp:size=100m"},
		ReadOnly: true,
	})
	r := Analyze(c)
	if r.Summary.TmpNoSizeLimit != 0 {
		t.Fatal("expected no finding for sized tmpfs")
	}
}

func TestReadOnlyNoTmpfsFinding(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:     "agent",
		ReadOnly: true,
	})
	r := Analyze(c)
	if r.Summary.TmpNoTmpfs != 0 {
		t.Fatal("read-only rootfs should not trigger no-tmpfs finding")
	}
}

func TestVarTmpPath(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/host/var/tmp:/var/tmp"},
	})
	r := Analyze(c)
	if r.Summary.TmpHostMounted == 0 {
		t.Fatal("expected /var/tmp host mount finding")
	}
}

func TestDevShmPath(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/host/shm:/dev/shm"},
	})
	r := Analyze(c)
	if r.Summary.TmpHostMounted == 0 {
		t.Fatal("expected /dev/shm host mount finding")
	}
}

func TestRunPath(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"./run:/run"},
	})
	r := Analyze(c)
	if r.Summary.TmpHostMounted == 0 {
		t.Fatal("expected /run host mount finding")
	}
}

func TestNoFindings(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:     "safe",
		ReadOnly: true,
		Tmpfs:    []string{"/tmp:size=50m"},
	})
	r := Analyze(c)
	if r.Summary.TmpHostMounted != 0 {
		t.Fatal("expected no host mount findings for safe service")
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Volumes: []string{"/host:/tmp"}},
		compose.Service{Name: "b", Volumes: []string{"/host:/var/tmp"}},
	)
	r := Analyze(c)
	if r.Summary.TmpHostMounted != 2 {
		t.Fatalf("expected 2 host mounts, got %d", r.Summary.TmpHostMounted)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/host:/tmp"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Temporary File") {
		t.Fatal("expected header in output")
	}
	if !strings.Contains(text, "agent") {
		t.Fatal("expected service name in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Findings:           0") {
		t.Fatal("expected 0 findings in text")
	}
}

func TestIsTmpPath(t *testing.T) {
	if !isTmpPath("/tmp") {
		t.Fatal("expected /tmp to match")
	}
	if !isTmpPath("/tmp/foo") {
		t.Fatal("expected /tmp/foo to match")
	}
	if isTmpPath("/home") {
		t.Fatal("expected /home to not match")
	}
}
