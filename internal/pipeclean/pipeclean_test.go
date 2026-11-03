package pipeclean

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func findRule(r Report, rule string) *Finding {
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return &f
			}
		}
	}
	return nil
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	s.Volumes = []string{"/data:/app/data"}
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for clean service, got %d", r.Summary.TotalFindings)
	}
}

func TestWritableFifoMount(t *testing.T) {
	s := svc("worker")
	s.Volumes = []string{"/host/tmp:/tmp"}
	c := mkCollected(s)
	r := Analyze(c)
	f := findRule(r, "writable_fifo_mount")
	if f == nil {
		t.Fatal("expected writable_fifo_mount finding")
	}
	if f.Level != "high" {
		t.Fatalf("expected high level, got %s", f.Level)
	}
}

func TestWritableFifoMountDevShm(t *testing.T) {
	s := svc("ipc")
	s.Volumes = []string{"/host/shm:/dev/shm"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_fifo_mount") == nil {
		t.Fatal("expected writable_fifo_mount for /dev/shm")
	}
}

func TestReadOnlyFifoMountNoFinding(t *testing.T) {
	s := svc("reader")
	s.Volumes = []string{"/host/tmp:/tmp:ro"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_fifo_mount") != nil {
		t.Fatal("read-only mount should not trigger writable_fifo_mount")
	}
}

func TestSharedPipePath(t *testing.T) {
	s1 := svc("producer")
	s1.Volumes = []string{"/tmp:/tmp"}
	s2 := svc("consumer")
	s2.Volumes = []string{"/tmp:/tmp"}
	c := mkCollected(s1, s2)
	r := Analyze(c)
	if findRule(r, "shared_pipe_path") == nil {
		t.Fatal("expected shared_pipe_path when two services share /tmp")
	}
}

func TestNoSharedPathDifferentMounts(t *testing.T) {
	s1 := svc("a")
	s1.Volumes = []string{"/tmp:/data1"}
	s2 := svc("b")
	s2.Volumes = []string{"/tmp:/data2"}
	c := mkCollected(s1, s2)
	r := Analyze(c)
	if findRule(r, "shared_pipe_path") != nil {
		t.Fatal("different container paths should not trigger shared_pipe_path")
	}
}

func TestUnsafeMkfifoInCommand(t *testing.T) {
	s := svc("pipe-maker")
	s.Command = []string{"sh", "-c", "mkfifo /tmp/pipe && cat /tmp/pipe"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_mkfifo_usage") == nil {
		t.Fatal("expected unsafe_mkfifo_usage for mkfifo in command")
	}
}

func TestUnsafeMkfifoInEntrypoint(t *testing.T) {
	s := svc("pipe-ep")
	s.Entrypoint = []string{"mkfifo", "/var/run/app.pipe"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_mkfifo_usage") == nil {
		t.Fatal("expected unsafe_mkfifo_usage for mkfifo in entrypoint")
	}
}

func TestPipeEscapeRisk(t *testing.T) {
	s := svc("ipc-svc")
	s.Volumes = []string{"/host/fifo_channel:/app/named_pipe"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "pipe_escape_risk") == nil {
		t.Fatal("expected pipe_escape_risk for pipe-indicator volume")
	}
}

func TestWorldWritablePipeEnv(t *testing.T) {
	s := svc("env-pipe")
	s.Environment = []string{"PIPE_PATH=/tmp/mypipe"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "world_writable_pipe") == nil {
		t.Fatal("expected world_writable_pipe for PIPE_PATH pointing to /tmp")
	}
}

func TestSafePipeEnvNoFinding(t *testing.T) {
	s := svc("safe")
	s.Environment = []string{"APP_MODE=production"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "world_writable_pipe") != nil {
		t.Fatal("non-pipe env vars should not trigger world_writable_pipe")
	}
}

func TestMissingPipeIsolation(t *testing.T) {
	s := svc("builder")
	s.Volumes = []string{"/host/tmp:/tmp"}
	s.CapAdd = []string{"MKNOD"}
	s.ReadOnly = false
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "missing_pipe_isolation") == nil {
		t.Fatal("expected missing_pipe_isolation for MKNOD cap with writable FIFO path")
	}
}

func TestMissingPipeIsolationSysAdmin(t *testing.T) {
	s := svc("admin")
	s.Volumes = []string{"/host/run:/run"}
	s.CapAdd = []string{"SYS_ADMIN"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "missing_pipe_isolation") == nil {
		t.Fatal("expected missing_pipe_isolation for SYS_ADMIN cap with writable FIFO path")
	}
}

func TestReadOnlyRootNoIsolationFinding(t *testing.T) {
	s := svc("locked")
	s.Volumes = []string{"/host/tmp:/tmp"}
	s.CapAdd = []string{"MKNOD"}
	s.ReadOnly = true
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "missing_pipe_isolation") != nil {
		t.Fatal("read-only rootfs should suppress missing_pipe_isolation")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("multi")
	s.Volumes = []string{"/tmp:/tmp"}
	s.Command = []string{"mkfifo", "/tmp/pipe"}
	s.CapAdd = []string{"MKNOD"}
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.WritableFifoMounts < 1 {
		t.Fatal("expected WritableFifoMounts > 0")
	}
	if r.Summary.UnsafeMkfifoUsage < 1 {
		t.Fatal("expected UnsafeMkfifoUsage > 0")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("pipe-svc")
	s.Volumes = []string{"/tmp:/tmp"}
	c := mkCollected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "pipe-svc") {
		t.Fatal("expected service name in text output")
	}
	if !strings.Contains(text, "Named Pipe") {
		t.Fatal("expected header in text output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/myproject"}
	r := Analyze(c)
	if r.Path != "/myproject" {
		t.Fatalf("expected /myproject, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("a")
	s1.Volumes = []string{"/tmp:/tmp"}
	s2 := svc("b")
	s2.Volumes = []string{"/data:/data"}
	c := mkCollected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestVarRunFifo(t *testing.T) {
	s := svc("daemon")
	s.Volumes = []string{"/host/run:/var/run"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_fifo_mount") == nil {
		t.Fatal("expected writable_fifo_mount for /var/run")
	}
}

func TestDevMqueueFifo(t *testing.T) {
	s := svc("mq")
	s.Volumes = []string{"/host/mq:/dev/mqueue"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_fifo_mount") == nil {
		t.Fatal("expected writable_fifo_mount for /dev/mqueue")
	}
}

func TestIsFifoPathSubdir(t *testing.T) {
	if !isFifoPath("/tmp/subdir") {
		t.Fatal("expected /tmp/subdir to be FIFO path")
	}
	if isFifoPath("/app/tmp") {
		t.Fatal("/app/tmp should not be FIFO path")
	}
}

func TestMknodIndicator(t *testing.T) {
	s := svc("dev")
	s.Command = []string{"mknod", "/tmp/fifo", "p"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_mkfifo_usage") == nil {
		t.Fatal("expected unsafe_mkfifo_usage for mknod command")
	}
}
