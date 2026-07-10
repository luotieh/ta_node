package intel

type ThreatIntel struct {
	ID                string    `json:"id" yaml:"id"`
	Type              string    `json:"type" yaml:"type"`
	Value             string    `json:"value" yaml:"value"`
	Category          string    `json:"category" yaml:"category"`
	Severity          string    `json:"severity" yaml:"severity"`
	Source            string    `json:"source" yaml:"source"`
	Description       string    `json:"description" yaml:"description"`
	Tags              []string  `json:"tags" yaml:"tags"`
	Enabled           bool      `json:"enabled" yaml:"enabled"`
	CreatedAt         int64     `json:"created_at" yaml:"created_at"`
	UpdatedAt         int64     `json:"updated_at" yaml:"updated_at"`
	ExpireAt          int64     `json:"expire_at,omitempty" yaml:"expire_at,omitempty"`
	RecommendedAction string    `json:"recommended_action,omitempty" yaml:"recommended_action,omitempty"`
	Evidence          *Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// Evidence carries the rich threat context delivered alongside an IOC (via the
// gateway zip feed). It is preserved through matching into pushed events for AI
// analysis. Absent for locally-authored IOCs.
type Evidence struct {
	Activity     string   `json:"activity,omitempty" yaml:"activity,omitempty"`
	ThreatLabels []string `json:"threat_labels,omitempty" yaml:"threat_labels,omitempty"`
	Source       string   `json:"source,omitempty" yaml:"source,omitempty"`
	CrossCheck   string   `json:"cross_check,omitempty" yaml:"cross_check,omitempty"`
	Confidence   string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	TLP          string   `json:"tlp,omitempty" yaml:"tlp,omitempty"`
	MISPEventID  string   `json:"misp_event_id,omitempty" yaml:"misp_event_id,omitempty"`
	Narrative    string   `json:"narrative,omitempty" yaml:"narrative,omitempty"`
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
