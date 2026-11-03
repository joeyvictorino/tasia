package capbound

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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestCapAddAll(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CapAdd: []string{"ALL"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_broad_grant") {
		t.Error("expected capbound_broad_grant for cap_add: ALL")
	}
	if r.Summary.BroadGrants != 1 {
		t.Errorf("expected 1 broad grant, got %d", r.Summary.BroadGrants)
	}
}

func TestDangerousCapSysAdmin(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CapAdd: []string{"SYS_ADMIN"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_dangerous_cap") {
		t.Error("expected capbound_dangerous_cap for SYS_ADMIN")
	}
	if r.Summary.DangerousCaps < 1 {
		t.Errorf("expected dangerous caps >= 1, got %d", r.Summary.DangerousCaps)
	}
}

func TestDangerousCapNetAdmin(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CapAdd: []string{"NET_ADMIN"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_dangerous_cap") {
		t.Error("expected capbound_dangerous_cap for NET_ADMIN")
	}
}

func TestDangerousCapSysPtrace(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CapAdd: []string{"SYS_PTRACE"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_dangerous_cap") {
		t.Error("expected capbound_dangerous_cap for SYS_PTRACE")
	}
}

func TestCAPPrefix(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CapAdd: []string{"CAP_SYS_ADMIN"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_dangerous_cap") {
		t.Error("expected capbound_dangerous_cap for CAP_SYS_ADMIN (with prefix)")
	}
}

func TestMissingDropWithAdd(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CapAdd: []string{"NET_BIND_SERVICE"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_missing_drop") {
		t.Error("expected capbound_missing_drop when cap_add without cap_drop")
	}
	if r.Summary.MissingDrops != 1 {
		t.Errorf("expected 1 missing drop, got %d", r.Summary.MissingDrops)
	}
}

func TestDropAllThenAddOk(t *testing.T) {
	c := collected(compose.Service{
		Name:    "svc",
		CapAdd:  []string{"NET_BIND_SERVICE"},
		CapDrop: []string{"ALL"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "capbound_missing_drop") {
		t.Error("should not flag missing_drop when cap_drop: ALL is set")
	}
}

func TestNoCapDropAll(t *testing.T) {
	c := collected(compose.Service{Name: "bare"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_no_cap_drop_all") {
		t.Error("expected capbound_no_cap_drop_all when no caps configured")
	}
	if r.Summary.NoCapDropAll != 1 {
		t.Errorf("expected 1 no_cap_drop_all, got %d", r.Summary.NoCapDropAll)
	}
}

func TestDangerousComboSysAdminNetAdmin(t *testing.T) {
	c := collected(compose.Service{
		Name:    "svc",
		CapAdd:  []string{"SYS_ADMIN", "NET_ADMIN"},
		CapDrop: []string{"ALL"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_dangerous_combo") {
		t.Error("expected capbound_dangerous_combo for SYS_ADMIN + NET_ADMIN")
	}
	if r.Summary.DangerousCombos < 1 {
		t.Errorf("expected dangerous combos >= 1, got %d", r.Summary.DangerousCombos)
	}
}

func TestDangerousComboSysAdminPtrace(t *testing.T) {
	c := collected(compose.Service{
		Name:    "svc",
		CapAdd:  []string{"SYS_ADMIN", "SYS_PTRACE"},
		CapDrop: []string{"ALL"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "capbound_dangerous_combo") {
		t.Error("expected capbound_dangerous_combo for SYS_ADMIN + SYS_PTRACE")
	}
}

func TestSafeCapConfig(t *testing.T) {
	c := collected(compose.Service{
		Name:    "safe",
		CapAdd:  []string{"NET_BIND_SERVICE"},
		CapDrop: []string{"ALL"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "capbound_dangerous_cap") {
		t.Error("NET_BIND_SERVICE alone should not be dangerous")
	}
	if hasRule(r.Services[0], "capbound_dangerous_combo") {
		t.Error("single safe cap should not trigger combo")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CapAdd: []string{"SYS_ADMIN"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CapAdd: []string{"NET_ADMIN"}})
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

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", CapAdd: []string{"SYS_ADMIN"}, CapDrop: []string{"ALL"}},
		compose.Service{Name: "db"},
		compose.Service{Name: "safe", CapAdd: []string{"NET_BIND_SERVICE"}, CapDrop: []string{"ALL"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.DangerousCaps < 1 {
		t.Error("expected at least 1 dangerous cap")
	}
}
