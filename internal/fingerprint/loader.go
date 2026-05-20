package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type threatFile struct {
	Threat struct {
		Rules map[string]PatternRule `json:"rules"`
	} `json:"threat"`
}

func LoadRules(path string) ([]PatternRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tf threatFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, err
	}
	rules := make([]PatternRule, 0, len(tf.Threat.Rules))
	for id, r := range tf.Threat.Rules {
		r.ID = id
		if r.Deleted == 0 {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func LoadDir(patternDir string) ([]PatternRule, error) {
	return LoadRules(filepath.Join(patternDir, "threat.json"))
}
