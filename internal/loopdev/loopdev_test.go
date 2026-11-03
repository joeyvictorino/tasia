package loopdev

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestNoDevices(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for service with no devices, got %d", r.Summary.TotalFindings)
	}
}

func TestLoopDevice(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "builder",
		Devices: []string{"/dev/loop0:/dev/loop0"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_loop_device" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_loop_device finding")
	}
}

func TestBlockDevice(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "storage",
		Devices: []string{"/dev/sda:/dev/sda"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_block_device" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_block_device finding")
	}
}

func TestFuseDevice(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "mount-svc",
		Devices: []string{"/dev/fuse:/dev/fuse"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_fuse_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_fuse_mount finding")
	}
}

func TestRawMemoryAccess(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "debug",
		Devices: []string{"/dev/mem:/dev/mem"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_raw_access" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_raw_access finding for /dev/mem")
	}
}

func TestKmemAccess(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "kernel-debug",
		Devices: []string{"/dev/kmem:/dev/kmem"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_raw_access" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_raw_access finding for /dev/kmem")
	}
}

func TestVolumeDeviceMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "vol-dev",
		Volumes: []string{"/dev/sda1:/mnt/disk"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_block_device" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_block_device finding from volume mount")
	}
}

func TestPrivilegedWithDevices(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "priv-dev",
		Privileged: true,
		Devices:    []string{"/dev/loop0:/dev/loop0"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_privileged_device" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_privileged_device finding")
	}
}

func TestPrivilegedNoDevices(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "priv-only",
		Privileged: true,
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_privileged_device" {
				t.Error("should not flag privileged without devices")
			}
		}
	}
}

func TestRawIOPrivileged(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "rawio",
		Privileged: true,
		CapAdd:     []string{"SYS_RAWIO"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_rawio_privileged" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_rawio_privileged finding")
	}
}

func TestMknodWritable(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:   "mknod-svc",
		CapAdd: []string{"MKNOD"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_mknod_writable" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_mknod_writable finding")
	}
}

func TestMknodReadOnly(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:     "mknod-ro",
		CapAdd:   []string{"MKNOD"},
		ReadOnly: true,
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_mknod_writable" {
				t.Error("should not flag MKNOD on read-only filesystem")
			}
		}
	}
}

func TestNvmeDevice(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "nvme-svc",
		Devices: []string{"/dev/nvme0n1:/dev/nvme0n1"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_block_device" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_block_device finding for NVMe device")
	}
}

func TestSummary(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Devices: []string{"/dev/loop0:/dev/loop0"}},
		compose.Service{Name: "b", Devices: []string{"/dev/fuse:/dev/fuse"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.LoopDeviceMount != 1 {
		t.Errorf("expected 1 loop mount, got %d", r.Summary.LoopDeviceMount)
	}
	if r.Summary.FuseMount != 1 {
		t.Errorf("expected 1 fuse mount, got %d", r.Summary.FuseMount)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "dev-svc",
		Devices: []string{"/dev/loop0:/dev/loop0"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestCapAllRawIO(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "all-caps",
		Privileged: true,
		CapAdd:     []string{"ALL"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopdev_rawio_privileged" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected loopdev_rawio_privileged for CAP ALL")
	}
}
