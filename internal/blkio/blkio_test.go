package blkio

import (
	"encoding/json"
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

func TestNoBlkioConfig(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_weight_missing" {
			found = true
		}
	}
	if !found {
		t.Error("expected blkio_weight_missing finding")
	}
}

func TestNormalWeight(t *testing.T) {
	c := collected(compose.Service{Name: "web", BlkioWeight: 500})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_weight_missing" {
			t.Error("should not flag weight_missing when weight is set")
		}
		if f.Rule == "blkio_weight_extreme" {
			t.Error("should not flag extreme for normal weight 500")
		}
	}
}

func TestExtremeWeightLow(t *testing.T) {
	c := collected(compose.Service{Name: "worker", BlkioWeight: 10})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_weight_extreme" {
			found = true
		}
	}
	if !found {
		t.Error("expected blkio_weight_extreme finding for weight 10")
	}
}

func TestExtremeWeightHigh(t *testing.T) {
	c := collected(compose.Service{Name: "worker", BlkioWeight: 1000})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_weight_extreme" {
			found = true
		}
	}
	if !found {
		t.Error("expected blkio_weight_extreme finding for weight 1000")
	}
}

func TestNoDeviceLimits(t *testing.T) {
	c := collected(compose.Service{Name: "db", BlkioWeight: 500})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_no_device_limits" {
			found = true
		}
	}
	if !found {
		t.Error("expected blkio_no_device_limits when weight set but no device limits")
	}
}

func TestWithDeviceLimits(t *testing.T) {
	c := collected(compose.Service{
		Name:       "db",
		BlkioWeight: 500,
		BlkioDeviceReadBps: []compose.BlkioRateDevice{
			{Path: "/dev/sda", Rate: "10mb"},
		},
		BlkioDeviceReadIOps: []compose.BlkioRateDevice{
			{Path: "/dev/sda", Rate: "1000"},
		},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_no_device_limits" {
			t.Error("should not flag no_device_limits when device limits are present")
		}
		if f.Rule == "blkio_weight_missing" {
			t.Error("should not flag weight_missing when weight is set")
		}
	}
}

func TestNoIopsLimit(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		BlkioWeight: 500,
		BlkioDeviceReadBps: []compose.BlkioRateDevice{
			{Path: "/dev/sda", Rate: "50mb"},
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_no_iops_limit" {
			found = true
		}
	}
	if !found {
		t.Error("expected blkio_no_iops_limit when bps limits set but no iops")
	}
}

func TestUnbalancedWeights(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", BlkioWeight: 10},
		compose.Service{Name: "db", BlkioWeight: 900},
	)
	r := Analyze(c)
	foundWeb := false
	foundDB := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "blkio_unbalanced_weights" {
				if sr.Service == "web" {
					foundWeb = true
				}
				if sr.Service == "db" {
					foundDB = true
				}
			}
		}
	}
	if !foundWeb || !foundDB {
		t.Error("expected unbalanced_weights finding on both services")
	}
}

func TestBalancedWeights(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", BlkioWeight: 400},
		compose.Service{Name: "api", BlkioWeight: 600},
	)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "blkio_unbalanced_weights" {
				t.Errorf("unexpected unbalanced finding on %s", sr.Service)
			}
		}
	}
}

func TestNonStandardDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		BlkioWeight: 500,
		BlkioDeviceReadBps: []compose.BlkioRateDevice{
			{Path: "/dev/mapper/my-volume", Rate: "10mb"},
		},
		BlkioDeviceReadIOps: []compose.BlkioRateDevice{
			{Path: "/dev/mapper/my-volume", Rate: "100"},
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_rate_limit_missing_device" {
			found = true
		}
	}
	if !found {
		t.Error("expected blkio_rate_limit_missing_device for non-standard device path")
	}
}

func TestStandardDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		BlkioWeight: 500,
		BlkioDeviceReadBps: []compose.BlkioRateDevice{
			{Path: "/dev/sda", Rate: "10mb"},
		},
		BlkioDeviceReadIOps: []compose.BlkioRateDevice{
			{Path: "/dev/sda", Rate: "100"},
		},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "blkio_rate_limit_missing_device" {
			t.Error("should not flag standard /dev/sda as missing device")
		}
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", BlkioWeight: 500},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithWeight != 1 {
		t.Errorf("expected 1 with weight, got %d", r.Summary.WithWeight)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", BlkioWeight: 500})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "Block I/O Audit") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "web", BlkioWeight: 500})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}

func TestEmptyServices(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
