package intel

import (
	"os"
	"path/filepath"

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
