package intel

type ThreatIntel struct {
	ID          string   `json:"id" yaml:"id"`
	Type        string   `json:"type" yaml:"type"`
	Value       string   `json:"value" yaml:"value"`
	Category    string   `json:"category" yaml:"category"`
	Severity    string   `json:"severity" yaml:"severity"`
	Source      string   `json:"source" yaml:"source"`
	Description string   `json:"description" yaml:"description"`
	Tags        []string `json:"tags" yaml:"tags"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	CreatedAt   int64    `json:"created_at" yaml:"created_at"`
	UpdatedAt   int64    `json:"updated_at" yaml:"updated_at"`
	ExpireAt    int64    `json:"expire_at,omitempty" yaml:"expire_at,omitempty"`
}

type File struct {
	Items []ThreatIntel `json:"items" yaml:"items"`
}

type StoreStats struct {
	Total         int            `json:"total"`
	Enabled       int            `json:"enabled"`
	Expired       int            `json:"expired"`
	ByType        map[string]int `json:"by_type"`
	BySource      map[string]int `json:"by_source"`
	LastUpdatedAt int64          `json:"last_updated_at"`
	Version       int64          `json:"version"`
}
