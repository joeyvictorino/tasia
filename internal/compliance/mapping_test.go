package compliance

import "testing"

func TestMappingIndexCoversMultipleRules(t *testing.T) {
	idx := MappingIndex()
	if len(idx) < 15 {
		t.Errorf("mapping index has %d rules, want at least 15", len(idx))
	}
	if ctrls, ok := idx["privileged_container"]; !ok || len(ctrls) == 0 {
		t.Error("privileged_container should have controls")
	}
}

func TestFrameworks(t *testing.T) {
	fws := Frameworks()
	if len(fws) != 3 {
		t.Errorf("expected 3 frameworks, got %d", len(fws))
	}
}

func TestControlsForFramework(t *testing.T) {
	for _, fw := range Frameworks() {
		ctrls := ControlsForFramework(fw)
		if len(ctrls) == 0 {
			t.Errorf("framework %s has no controls", fw)
		}
		for _, c := range ctrls {
			if c.Framework != fw {
				t.Errorf("control %s has framework %s, want %s", c.ControlID, c.Framework, fw)
			}
		}
	}
}

func TestMappingIndexAllHaveControls(t *testing.T) {
	idx := MappingIndex()
	for ruleID, ctrls := range idx {
		if len(ctrls) == 0 {
			t.Errorf("rule %s has empty controls", ruleID)
		}
		for _, c := range ctrls {
			if c.Framework == "" || c.ControlID == "" || c.Name == "" {
				t.Errorf("rule %s has incomplete control: %+v", ruleID, c)
			}
		}
	}
}
