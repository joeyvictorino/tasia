package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTagsListEmpty(t *testing.T) {
	dir := t.TempDir()
	err := runTags([]string{"list", "--path", dir})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTagsListJSON(t *testing.T) {
	dir := t.TempDir()
	err := runTags([]string{"list", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTagsAdd(t *testing.T) {
	dir := t.TempDir()
	err := runTags([]string{"add", "--path", dir, "--rule", "exposed_port", "--tag", "accepted-risk"})
	if err != nil {
		t.Fatal(err)
	}

	store, _, err := loadTagStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(store.Entries))
	}
	if store.Entries[0].Tags[0] != "accepted-risk" {
		t.Fatalf("wrong tag: %v", store.Entries[0].Tags)
	}
}

func TestTagsAddWithNote(t *testing.T) {
	dir := t.TempDir()
	err := runTags([]string{"add", "--path", dir, "--rule", "docker_socket", "--tag", "wontfix", "--note", "test env only"})
	if err != nil {
		t.Fatal(err)
	}

	store, _, _ := loadTagStore(dir)
	if store.Entries[0].Note != "test env only" {
		t.Fatalf("note not saved: %q", store.Entries[0].Note)
	}
}

func TestTagsAddDuplicate(t *testing.T) {
	dir := t.TempDir()
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "t1"})
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "t1"})

	store, _, _ := loadTagStore(dir)
	if len(store.Entries) != 1 || len(store.Entries[0].Tags) != 1 {
		t.Fatal("duplicate tag was added")
	}
}

func TestTagsAddMultipleTags(t *testing.T) {
	dir := t.TempDir()
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "alpha"})
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "beta"})

	store, _, _ := loadTagStore(dir)
	if len(store.Entries[0].Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(store.Entries[0].Tags))
	}
}

func TestTagsRemove(t *testing.T) {
	dir := t.TempDir()
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "t1"})
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "t2"})

	err := runTags([]string{"remove", "--path", dir, "--rule", "r1", "--tag", "t1"})
	if err != nil {
		t.Fatal(err)
	}

	store, _, _ := loadTagStore(dir)
	if len(store.Entries) != 1 || store.Entries[0].Tags[0] != "t2" {
		t.Fatal("wrong state after remove")
	}
}

func TestTagsRemoveLastTag(t *testing.T) {
	dir := t.TempDir()
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "only"})
	runTags([]string{"remove", "--path", dir, "--rule", "r1", "--tag", "only"})

	store, _, _ := loadTagStore(dir)
	if len(store.Entries) != 0 {
		t.Fatal("entry should be removed when last tag is deleted")
	}
}

func TestTagsRemoveNotFound(t *testing.T) {
	dir := t.TempDir()
	err := runTags([]string{"remove", "--path", dir, "--rule", "nope", "--tag", "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTagsMissingFlags(t *testing.T) {
	dir := t.TempDir()
	if err := runTags([]string{"add", "--path", dir}); err == nil {
		t.Fatal("expected error for missing --rule and --tag")
	}
	if err := runTags([]string{"remove", "--path", dir}); err == nil {
		t.Fatal("expected error for missing flags")
	}
}

func TestTagsFilterByTag(t *testing.T) {
	dir := t.TempDir()
	runTags([]string{"add", "--path", dir, "--rule", "r1", "--tag", "risk"})
	runTags([]string{"add", "--path", dir, "--rule", "r2", "--tag", "review"})

	err := runTags([]string{"list", "--path", dir, "--tag", "risk"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTagsUnknownSubcommand(t *testing.T) {
	err := runTags([]string{"frobnicate"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTagsDefaultSubcommand(t *testing.T) {
	err := runTags(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestTagStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, ".tasia", "tags.json")

	store := &tagStore{
		Entries: []tagEntry{
			{Rule: "r1", Tags: []string{"a", "b"}, Note: "test"},
		},
	}
	if err := saveTagStore(storePath, store); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(storePath)
	var loaded tagStore
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].Note != "test" {
		t.Fatalf("roundtrip failed: %+v", loaded)
	}
}
