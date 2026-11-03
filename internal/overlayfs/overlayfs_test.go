package overlayfs

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestHasOverlayVolume(t *testing.T) {
	if !hasOverlayVolume([]string{"/data/overlay:/mnt"}) {
		t.Error("expected overlay volume detected")
	}
	if !hasOverlayVolume([]string{"upperdir=/data:/mnt"}) {
		t.Error("expected upperdir volume detected")
	}
	if hasOverlayVolume([]string{"/data:/app"}) {
		t.Error("expected no overlay in normal volume")
	}
}

func TestHasSensitiveMountPath(t *testing.T) {
	if !hasSensitiveMountPath([]string{"/host:/etc/config"}) {
		t.Error("expected sensitive /etc path detected")
	}
	if !hasSensitiveMountPath([]string{"/host:/proc/self"}) {
		t.Error("expected sensitive /proc path detected")
	}
	if hasSensitiveMountPath([]string{"/host:/app"}) {
		t.Error("expected no sensitive path in /app")
	}
}

func TestIsMountReadOnly(t *testing.T) {
	if !isMountReadOnly("/src:/dst:ro") {
		t.Error("expected read-only detected")
	}
	if isMountReadOnly("/src:/dst:rw") {
		t.Error("expected not read-only for rw")
	}
	if isMountReadOnly("/src:/dst") {
		t.Error("expected not read-only without options")
	}
}

func TestAnalyzeServiceOverlayVolume(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Image:   "myimage",
		Volumes: []string{"/data/overlay:/mnt"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "overlay_volume_mount" {
			found = true
		}
	}
	if !found {
		t.Error("expected overlay_volume_mount finding")
	}
}

func TestAnalyzeServiceSensitiveWritable(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Image:   "myimage",
		Volumes: []string{"/host:/etc"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "sensitive_path_writable" {
			found = true
		}
	}
	if !found {
		t.Error("expected sensitive_path_writable finding")
	}
}

func TestAnalyzeServicePrivilegedWithVolumes(t *testing.T) {
	svc := compose.Service{
		Name:       "app",
		Image:      "myimage",
		Privileged: true,
		Volumes:    []string{"/data:/mnt"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "privileged_with_volumes" {
			found = true
		}
	}
	if !found {
		t.Error("expected privileged_with_volumes finding")
	}
}

func TestAnalyzeServiceClean(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Image:   "myimage",
		Volumes: []string{"/data:/app"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings for clean service, got %d", len(sr.Findings))
	}
}

func TestAnalyzeDockerfileOverlayMount(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM ubuntu\nRUN mount -t overlay overlay /merged",
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "overlay_mount_in_build" {
			found = true
		}
	}
	if !found {
		t.Error("expected overlay_mount_in_build finding")
	}
}

func TestAnalyzeDockerfileFuseOverlay(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM ubuntu\nRUN apt-get install fuse-overlayfs",
	}
	dr := analyzeDockerfile(df)
	found := false
	for _, f := range dr.Findings {
		if f.Rule == "fuse_overlayfs_usage" {
			found = true
		}
	}
	if !found {
		t.Error("expected fuse_overlayfs_usage finding")
	}
}

func TestAnalyzeDockerfileClean(t *testing.T) {
	df := collect.Dockerfile{
		Path:    "Dockerfile",
		Content: "FROM nginx\nRUN apt-get update",
	}
	dr := analyzeDockerfile(df)
	if len(dr.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(dr.Findings))
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx", Volumes: []string{"/data/overlay:/mnt"}},
					{Name: "api", Image: "myapp"},
				},
			},
		},
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM ubuntu\nRUN mount -t overlay overlay /merged"},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalDockerfiles != 1 {
		t.Errorf("expected 1 dockerfile, got %d", r.Summary.TotalDockerfiles)
	}
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path:     "docker-compose.yml",
				Services: []compose.Service{{Name: "svc1", Image: "nginx", Volumes: []string{"/data/overlay:/mnt"}}},
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "OverlayFS") {
		t.Error("expected header in text output")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{Service: "a", Findings: []Finding{{Rule: "overlay_volume_mount"}, {Rule: "sensitive_path_writable"}}},
	}
	dockerfiles := []DockerfileResult{
		{File: "Dockerfile", Findings: []Finding{{Rule: "overlay_mount_in_build"}}},
	}
	s := summarize(services, dockerfiles)
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.WritableOverlay != 1 {
		t.Errorf("expected 1 writable overlay, got %d", s.WritableOverlay)
	}
}
