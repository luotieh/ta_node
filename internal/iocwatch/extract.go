package iocwatch

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"ta_node/internal/intel"
)

// errIncomplete signals a zip that cannot be opened yet — treated as still
// being written by the gateway and retried on a later scan.
var errIncomplete = errors.New("zip incomplete")

// maxZipUncompressed caps total decompressed bytes read from a single zip to
// bound memory against a malformed or hostile archive.
const maxZipUncompressed = 256 << 20

// extractItems reads every *.yaml/*.yml entry in the zip and parses them as
// intel item files. A zip that fails to open returns errIncomplete; any other
// error (bad entry, oversized, malformed yaml) is returned as a hard failure.
func extractItems(path string, maxItems int) ([]intel.ThreatIntel, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errIncomplete
	}
	defer zr.Close()

	var items []intel.ThreatIntel
	var total int64
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open entry %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxZipUncompressed-total+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read entry %s: %w", f.Name, err)
		}
		total += int64(len(data))
		if total > maxZipUncompressed {
			return nil, fmt.Errorf("zip %s exceeds %d bytes uncompressed", path, maxZipUncompressed)
		}
		var fy intel.File
		if err := yaml.Unmarshal(data, &fy); err != nil {
			return nil, fmt.Errorf("parse entry %s: %w", f.Name, err)
		}
		items = append(items, fy.Items...)
		if maxItems > 0 && len(items) > maxItems {
			items = items[:maxItems]
			break
		}
	}
	return items, nil
}
