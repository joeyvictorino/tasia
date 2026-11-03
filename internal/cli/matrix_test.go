package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatrixEmpty(t *testing.T) {
	dir := t.TempDir()
	err := runMatrix([]string{"--path", dir})
	if err != nil {
		t.Fatalf("matrix empty: %v", err)
	}
}

func TestMatrixJSON(t *testing.T) {
	dir := t.TempDir()
	err := runMatrix([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMatrixWithFindings(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runMatrix([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestComputeRiskLevel(t *testing.T) {
	tests := []struct {
		sev, likelihood, expected string
	}{
		{"critical", "high", "critical"},
		{"high", "high", "critical"},
		{"high", "medium", "high"},
		{"medium", "medium", "medium"},
		{"low", "low", "low"},
	}
	for _, tt := range tests {
		got := computeRiskLevel(tt.sev, tt.likelihood)
		if got != tt.expected {
			t.Errorf("computeRiskLevel(%s, %s) = %s, want %s", tt.sev, tt.likelihood, got, tt.expected)
		}
	}
}

func TestSevOrdinal(t *testing.T) {
	if sevOrdinal("critical") != 4 {
		t.Error("critical should be 4")
	}
	if sevOrdinal("low") != 1 {
		t.Error("low should be 1")
	}
}

func TestRiskOrdinal(t *testing.T) {
	if riskOrdinal("critical") <= riskOrdinal("high") {
		t.Error("critical should rank higher than high")
	}
}
