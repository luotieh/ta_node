package fingerprint

type PatternRule struct {
	ID       string `json:"-"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	IsHTTP   int    `json:"is_http"`
	Part     string `json:"part"`
	Regex    string `json:"regex"`
	Deleted  int    `json:"deleted"`
}

type FingerprintHit struct {
	RuleID       string `json:"rule_id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	MatchFrom    int    `json:"match_from"`
	MatchTo      int    `json:"match_to"`
	HitTimeUsec  uint64 `json:"hit_time_usec"`
	EvidenceFile string `json:"evidence_file,omitempty"`
}

type compiledRule struct {
	PatternRule
	re matcher
}

type matcher interface {
	FindIndex([]byte) []int
}
