package iocsync

import (
	"path/filepath"
	"testing"
)

// TestExtractItemsTruncatesAtMaxItems verifies that a zip containing more
// items than maxItems is truncated to exactly maxItems, rather than
// returning the full (over-limit) set or erroring out.
func TestExtractItemsTruncatesAtMaxItems(t *testing.T) {
	dir := t.TempDir()
	body := `items:
- {id: otx-1, type: domain, value: e1.example.com, enabled: true}
- {id: otx-2, type: domain, value: e2.example.com, enabled: true}
- {id: otx-3, type: domain, value: e3.example.com, enabled: true}
- {id: otx-4, type: domain, value: e4.example.com, enabled: true}
- {id: otx-5, type: domain, value: e5.example.com, enabled: true}
`
	path := filepath.Join(dir, "many.zip")
	writeZip(t, path, map[string]string{"a.yaml": body})

	const maxItems = 2
	items, err := extractItems(path, maxItems)
	if err != nil {
		t.Fatalf("extractItems returned error: %v", err)
	}
	if len(items) != maxItems {
		t.Fatalf("want %d items (truncated), got %d", maxItems, len(items))
	}
}
