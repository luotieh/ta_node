package intel

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreSyncSourceUpsertStatsAndPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intel.yaml")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(ThreatIntel{ID: "local", Type: "ip", Value: "10.0.0.1", Source: "local", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.SyncSource("Threat Intel Hub", []ThreatIntel{
		{ID: "hub-old", Type: "domain", Value: "old.example.com", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SyncSource("Threat Intel Hub", []ThreatIntel{
		{ID: "hub-new", Type: "domain", Value: "new.example.com", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("local"); !ok {
		t.Fatal("local IOC was removed by source sync")
	}
	if _, ok := store.Get("hub-old"); ok {
		t.Fatal("old source IOC was not removed")
	}
	if it, ok := store.Get("hub-new"); !ok || it.Source != "Threat Intel Hub" {
		t.Fatalf("new source IOC missing or wrong source: %#v", it)
	}
	if err := store.UpsertMany([]ThreatIntel{
		{ID: "hub-new", Type: "domain", Value: "changed.example.com", Source: "Threat Intel Hub", Enabled: true},
		{ID: "expired", Type: "ip", Value: "192.0.2.1", Source: "Threat Intel Hub", Enabled: true, ExpireAt: time.Now().Unix() - 1},
	}); err != nil {
		t.Fatal(err)
	}
	if it, _ := store.Get("hub-new"); it.Value != "changed.example.com" {
		t.Fatalf("upsert did not update existing IOC: %#v", it)
	}
	stats := store.Stats()
	if stats.Total != 3 || stats.BySource["local"] != 1 || stats.ByType["domain"] != 1 || stats.Expired != 1 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if deleted := store.PruneExpired(time.Now().Unix()); deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if _, ok := store.Get("expired"); ok {
		t.Fatal("expired IOC was not pruned")
	}
}
