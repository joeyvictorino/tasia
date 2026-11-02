package rules

import (
	"testing"
)

func TestCatalogNotEmpty(t *testing.T) {
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("catalog should not be empty")
	}
}

func TestCatalogUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Catalog() {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID in catalog: %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestCatalogFieldsPopulated(t *testing.T) {
	for _, r := range Catalog() {
		if r.ID == "" {
			t.Error("rule with empty ID")
		}
		if r.Default == "" {
			t.Errorf("rule %s has empty default severity", r.ID)
		}
		if r.Title == "" {
			t.Errorf("rule %s has empty title", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty description", r.ID)
		}
		if r.Category == "" {
			t.Errorf("rule %s has empty category", r.ID)
		}
	}
}

func TestCatalogCoversExpectedCount(t *testing.T) {
	cat := Catalog()
	if len(cat) != 36 {
		t.Errorf("catalog has %d rules, expected 36", len(cat))
	}
}
