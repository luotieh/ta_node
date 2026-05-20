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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
