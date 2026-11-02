package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestBuildInventoryEmpty(t *testing.T) {
	inv := buildInventoryFromFiles(nil)
	if len(inv.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(inv.Services))
	}
	if len(inv.Ports) != 0 {
		t.Errorf("expected 0 ports, got %d", len(inv.Ports))
	}
}

func TestBuildInventoryServices(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
  webui:
    image: ghcr.io/open-webui/open-webui
    ports:
      - "3000:8080"
  redis:
    image: redis:7
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	inv := buildInventoryFromFiles([]compose.File{*f})

	if len(inv.Services) != 3 {
		t.Fatalf("expected 3 services, got %d", len(inv.Services))
	}

	categories := map[string]string{}
	for _, s := range inv.Services {
		categories[s.Name] = s.Category
	}
	if categories["ollama"] != "inference" {
		t.Errorf("ollama should be inference, got %s", categories["ollama"])
	}
	if categories["webui"] != "ui" {
		t.Errorf("webui should be ui, got %s", categories["webui"])
	}
	if categories["redis"] != "datastore" {
		t.Errorf("redis should be datastore, got %s", categories["redis"])
	}
}

func TestBuildInventoryPorts(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
    ports:
      - "127.0.0.1:8080:8080"
      - "9090:9090"
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	inv := buildInventoryFromFiles([]compose.File{*f})

	if len(inv.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(inv.Ports))
	}

	if inv.Ports[0].ContainerPort != 8080 {
		t.Errorf("first port container should be 8080, got %d", inv.Ports[0].ContainerPort)
	}
}

func TestBuildInventoryVolumes(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	inv := buildInventoryFromFiles([]compose.File{*f})

	if len(inv.Volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(inv.Volumes))
	}

	if inv.Volumes[1].ReadOnly != true {
		t.Error("second volume should be read-only")
	}
	if inv.Volumes[0].Source != "pgdata" {
		t.Errorf("first volume source should be pgdata, got %s", inv.Volumes[0].Source)
	}
}

func TestBuildInventoryNetworks(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
networks:
  backend:
    internal: true
  frontend: {}
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	inv := buildInventoryFromFiles([]compose.File{*f})

	if len(inv.Networks) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(inv.Networks))
	}

	found := false
	for _, n := range inv.Networks {
		if n.Name == "backend" && n.Internal {
			found = true
		}
	}
	if !found {
		t.Error("backend network should be internal")
	}
}

func TestBuildInventoryEnvKeys(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
    environment:
      - API_KEY=secret
      - DEBUG=true
  worker:
    image: myworker
    environment:
      API_KEY: other
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	inv := buildInventoryFromFiles([]compose.File{*f})

	if len(inv.EnvKeys) != 2 {
		t.Fatalf("expected 2 env keys, got %d", len(inv.EnvKeys))
	}

	for _, ek := range inv.EnvKeys {
		if ek.Key == "API_KEY" && len(ek.Services) != 2 {
			t.Errorf("API_KEY should be used by 2 services, got %d", len(ek.Services))
		}
	}
}

func TestClassifyImage(t *testing.T) {
	tests := []struct {
		image    string
		expected string
	}{
		{"ollama/ollama", "inference"},
		{"ghcr.io/open-webui/open-webui", "ui"},
		{"qdrant/qdrant", "vector-db"},
		{"redis:7", "datastore"},
		{"postgres:16-alpine", "datastore"},
		{"nginx:latest", "other"},
		{"n8nio/n8n", "agent-runtime"},
		{"vllm/vllm-openai", "inference"},
	}
	for _, tt := range tests {
		got := classifyImage(tt.image)
		if got != tt.expected {
			t.Errorf("classifyImage(%q) = %q, want %q", tt.image, got, tt.expected)
		}
	}
}

func TestParseVolumeSpec(t *testing.T) {
	tests := []struct {
		input string
		src   string
		dst   string
		ro    bool
	}{
		{"/data", "", "/data", false},
		{"./src:/app", "./src", "/app", false},
		{"./conf:/etc/app:ro", "./conf", "/etc/app", true},
		{"vol:/data:rw", "vol", "/data", false},
	}
	for _, tt := range tests {
		src, dst, ro := parseVolumeSpec(tt.input)
		if src != tt.src || dst != tt.dst || ro != tt.ro {
			t.Errorf("parseVolumeSpec(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.input, src, dst, ro, tt.src, tt.dst, tt.ro)
		}
	}
}

func TestRunInventoryJSON(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runInventory([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("runInventory json failed: %v", err)
	}
}

func TestRunInventoryText(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runInventory([]string{"--path", dir})
	if err != nil {
		t.Fatalf("runInventory text failed: %v", err)
	}
}
