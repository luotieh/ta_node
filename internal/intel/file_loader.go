package intel

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"
)

func LoadFile(path string) ([]ThreatIntel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Items, nil
}

// LoadDir loads and concatenates every *.yaml/*.yml file in dir, parsing them
// concurrently. It returns all items found; callers dedup by ID. dir that is
// empty or has no rule files yields no items. A malformed or unreadable file
// fails the whole load so a bad drop-in never silently shrinks the IOC set.
func LoadDir(dir string) ([]ThreatIntel, error) {
	if dir == "" {
		return nil, nil
	}
	var paths []string
	for _, pat := range []string{"*.yaml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		paths = append(paths, m...)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	sort.Strings(paths)

	lists := make([][]ThreatIntel, len(paths))
	errs := make([]error, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, loadConcurrency())
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lists[i], errs[i] = LoadFile(p)
		}(i, p)
	}
	wg.Wait()

	var out []ThreatIntel
	for i, p := range paths {
		if errs[i] != nil {
			return nil, fmt.Errorf("load %s: %w", filepath.Base(p), errs[i])
		}
		out = append(out, lists[i]...)
	}
	return out, nil
}

func loadConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	if n > 16 {
		n = 16
	}
	return n
}

func SaveFile(path string, items []ThreatIntel) error {
	data, err := yaml.Marshal(File{Items: items})
	if err != nil {
		return err
	}
	return SaveFileAtomicBytes(path, data)
}

func SaveFileAtomic(path string, items []ThreatIntel) error {
	data, err := yaml.Marshal(File{Items: items})
	if err != nil {
		return err
	}
	return SaveFileAtomicBytes(path, data)
}

func SaveFileAtomicBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
