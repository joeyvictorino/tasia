package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeStatsBasic(t *testing.T) {
	stats := computeStats([]float64{10, 20, 30, 40, 50})
	if stats.MinMs != 10 {
		t.Fatalf("min: got %v, want 10", stats.MinMs)
	}
	if stats.MaxMs != 50 {
		t.Fatalf("max: got %v, want 50", stats.MaxMs)
	}
	if stats.AvgMs != 30 {
		t.Fatalf("avg: got %v, want 30", stats.AvgMs)
	}
	if stats.P50Ms != 30 {
		t.Fatalf("p50: got %v, want 30", stats.P50Ms)
	}
}

func TestComputeStatsEmpty(t *testing.T) {
	stats := computeStats(nil)
	if stats.MinMs != 0 || stats.MaxMs != 0 || stats.AvgMs != 0 {
		t.Fatalf("empty stats should be zero: %+v", stats)
	}
}

func TestComputeStatsSingle(t *testing.T) {
	stats := computeStats([]float64{42})
	if stats.MinMs != 42 || stats.MaxMs != 42 || stats.AvgMs != 42 {
		t.Fatalf("single: %+v", stats)
	}
}

func TestPercentile(t *testing.T) {
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	p50 := percentile(sorted, 50)
	if p50 < 5 || p50 > 6 {
		t.Fatalf("p50 of 1..10: got %v", p50)
	}
	p95 := percentile(sorted, 95)
	if p95 < 9 || p95 > 10 {
		t.Fatalf("p95 of 1..10: got %v", p95)
	}
}

func TestRunBenchSmallFixture(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runBench([]string{"--path", dir, "--iterations", "2", "--warmup", "1", "--format", "text"})
	if err != nil {
		t.Fatalf("runBench: %v", err)
	}
}

func TestRunBenchJSON(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
`), 0644)

	err := runBench([]string{"--path", dir, "--iterations", "2", "--warmup", "0", "--format", "json"})
	if err != nil {
		t.Fatalf("runBench json: %v", err)
	}
}

func TestRunBenchEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := runBench([]string{"--path", dir, "--iterations", "1", "--warmup", "0"})
	if err != nil {
		t.Fatalf("runBench empty: %v", err)
	}
}
