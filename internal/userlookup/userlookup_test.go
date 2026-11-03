package userlookup

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

func TestMissingUserDirective(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_missing_user") {
		t.Error("expected userlookup_missing_user when no user directive set")
	}
	if r.Summary.MissingUser != 1 {
		t.Errorf("expected 1 missing user, got %d", r.Summary.MissingUser)
	}
}

func TestExplicitRootUser(t *testing.T) {
	c := collected(compose.Service{Name: "db", User: "root"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_root_user") {
		t.Error("expected userlookup_root_user for user: root")
	}
	if r.Summary.RootUsers != 1 {
		t.Errorf("expected 1 root user, got %d", r.Summary.RootUsers)
	}
}

func TestRootByUID(t *testing.T) {
	c := collected(compose.Service{Name: "db", User: "0"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_root_user") {
		t.Error("expected userlookup_root_user for user: 0")
	}
}

func TestRootWithGroup(t *testing.T) {
	c := collected(compose.Service{Name: "db", User: "root:root", GroupName: "root"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_root_user") {
		t.Error("expected userlookup_root_user for user: root:root")
	}
}

func TestNumericOnlyUID(t *testing.T) {
	c := collected(compose.Service{Name: "app", User: "1000"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_numeric_uid") {
		t.Error("expected userlookup_numeric_uid for numeric user 1000")
	}
	if r.Summary.NumericOnly != 1 {
		t.Errorf("expected 1 numeric uid, got %d", r.Summary.NumericOnly)
	}
}

func TestNumericWithGroup(t *testing.T) {
	c := collected(compose.Service{Name: "app", User: "1000:1000", GroupName: "1000"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_numeric_uid") {
		t.Error("expected userlookup_numeric_uid for 1000:1000")
	}
}

func TestNamedUserNotNumeric(t *testing.T) {
	c := collected(compose.Service{Name: "app", User: "appuser"})
	r := Analyze(c)
	if hasRule(r.Services[0], "userlookup_numeric_uid") {
		t.Error("named user 'appuser' should not trigger numeric_uid")
	}
}

func TestMismatchedGroup(t *testing.T) {
	c := collected(compose.Service{Name: "svc", User: "daemon:users", GroupName: "users"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_mismatched_group") {
		t.Error("expected userlookup_mismatched_group for daemon:users")
	}
	if r.Summary.MismatchedGroups != 1 {
		t.Errorf("expected 1 mismatched group, got %d", r.Summary.MismatchedGroups)
	}
}

func TestHighPrivilegeUser(t *testing.T) {
	c := collected(compose.Service{Name: "svc", User: "daemon"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "userlookup_high_privilege") {
		t.Error("expected userlookup_high_privilege for daemon user")
	}
}

func TestSafeUser(t *testing.T) {
	c := collected(compose.Service{Name: "app", User: "appuser"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for safe user, got %d", len(r.Services[0].Findings))
	}
}

func TestSafeUserWithGroup(t *testing.T) {
	c := collected(compose.Service{Name: "app", User: "appuser:appgroup", GroupName: "appgroup"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for safe user:group, got %d", len(r.Services[0].Findings))
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
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "svc", User: "root"})
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
		compose.Service{Name: "web"},
		compose.Service{Name: "db", User: "root"},
		compose.Service{Name: "app", User: "appuser"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingUser != 1 {
		t.Errorf("expected 1 missing user, got %d", r.Summary.MissingUser)
	}
	if r.Summary.RootUsers != 1 {
		t.Errorf("expected 1 root user, got %d", r.Summary.RootUsers)
	}
}
