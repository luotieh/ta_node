package intel

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
)

type STIXEnvelope struct {
	Type    string       `json:"type"`
	Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Pattern     string   `json:"pattern"`
	Labels      []string `json:"labels"`
	Confidence  int      `json:"confidence"`
	Description string   `json:"description"`
	ValidFrom   string   `json:"valid_from"`
	ValidUntil  string   `json:"valid_until"`
}

type STIXParseResult struct {
	Items   []ThreatIntel `json:"items"`
	Skipped int           `json:"skipped"`
	Errors  []string      `json:"errors,omitempty"`
}

var stixPatterns = []struct {
	re  *regexp.Regexp
	typ string
}{
	{regexp.MustCompile(`^\[(?:ipv4-addr|ipv6-addr):value\s*=\s*'([^']+)'\]$`), "ip"},
	{regexp.MustCompile(`^\[domain-name:value\s*=\s*'([^']+)'\]$`), "domain"},
	{regexp.MustCompile(`^\[url:value\s*=\s*'([^']+)'\]$`), "url"},
	{regexp.MustCompile(`^\[ipv4-addr:value\s+ISSUBSET\s+'([^']+)'\]$`), "cidr"},
	{regexp.MustCompile(`^\[file:hashes\.(?:'[^']+'|[A-Za-z0-9_-]+)\s*=\s*'([^']+)'\]$`), "hash"},
}

func ParseSTIXIndicators(r io.Reader, defaultSource string) (STIXParseResult, error) {
	var env STIXEnvelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return STIXParseResult{}, err
	}
	var result STIXParseResult
	for _, obj := range env.Objects {
		it, ok := STIXIndicatorToThreatIntel(obj, defaultSource)
		if !ok {
			result.Skipped++
			if obj.ID != "" {
				result.Errors = append(result.Errors, "skipped "+obj.ID)
			}
			continue
		}
		result.Items = append(result.Items, it)
	}
	return result, nil
}

func STIXIndicatorToThreatIntel(obj STIXObject, defaultSource string) (ThreatIntel, bool) {
	if strings.ToLower(obj.Type) != "indicator" {
		return ThreatIntel{}, false
	}
	typ, value, ok := ParseSTIXPattern(obj.Pattern)
	if !ok {
		return ThreatIntel{}, false
	}
	now := time.Now().Unix()
	expireAt := int64(0)
	if obj.ValidUntil != "" {
		if t, err := time.Parse(time.RFC3339, obj.ValidUntil); err == nil {
			expireAt = t.Unix()
		}
	}
	category := categoryFromLabels(obj.Labels)
	if expireAt == 0 {
		expireAt = now + defaultTTL(typ, category)
	}
	source := strings.TrimSpace(defaultSource)
	if source == "" {
		source = "Threat Intel Hub"
	}
	id := obj.ID
	if id == "" {
		id = "stix-" + typ + "-" + value
	}
	return ThreatIntel{
		ID:          id,
		Type:        typ,
		Value:       value,
		Category:    category,
		Severity:    severityFromConfidence(obj.Confidence),
		Source:      source,
		Description: obj.Description,
		Tags:        obj.Labels,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpireAt:    expireAt,
	}, true
}

func ParseSTIXPattern(pattern string) (typ string, value string, ok bool) {
	pattern = strings.TrimSpace(pattern)
	for _, p := range stixPatterns {
		if match := p.re.FindStringSubmatch(pattern); len(match) == 2 {
			return p.typ, match[1], true
		}
	}
	return "", "", false
}

func severityFromConfidence(confidence int) string {
	switch {
	case confidence >= 90:
		return "critical"
	case confidence >= 70:
		return "high"
	case confidence >= 40:
		return "medium"
	default:
		return "low"
	}
}

func categoryFromLabels(labels []string) string {
	type labelPair struct{ key, category string }
	orderedLabels := []labelPair{
		{"c2", "c2"},
		{"ransomware", "ransomware"},
		{"phishing", "phishing"},
		{"malware", "malware"},
		{"botnet", "botnet"},
		{"exploit", "exploit"},
		{"webshell", "webshell"},
		{"scanner", "scanner"},
		{"network_activity", "network_activity"},
		{"command_and_control", "c2"},
		{"c2_server", "c2"},
		{"trojan", "malware"},
		{"stealer", "malware"},
		{"backdoor", "malware"},
		{"rat", "malware"},
		{"spyware", "malware"},
		{"dropper", "malware"},
		{"loader", "malware"},
		{"keylogger", "malware"},
		{"worm", "malware"},
		{"rootkit", "malware"},
		{"banker", "malware"},
		{"ddos", "botnet"},
		{"spam", "botnet"},
		{"proxy", "botnet"},
		{"credential_phishing", "phishing"},
		{"spear_phishing", "phishing"},
		{"whaling", "phishing"},
		{"smishing", "phishing"},
		{"vishing", "phishing"},
		{"sql_injection", "exploit"},
		{"sqli", "exploit"},
		{"xss", "exploit"},
		{"rce", "exploit"},
		{"lfi", "exploit"},
		{"csrf", "exploit"},
		{"ssrf", "exploit"},
		{"port_scan", "scanner"},
		{"vulnerability_scan", "scanner"},
		{"reconnaissance", "scanner"},
	}
	normalized := make([]string, len(labels))
	for i, label := range labels {
		normalized[i] = strings.ToLower(strings.TrimSpace(label))
	}
	// First pass: exact match, ordered by priority (c2 wins over malware)
	for _, pair := range orderedLabels {
		for _, label := range normalized {
			if label == pair.key {
				return pair.category
			}
		}
	}
	// Second pass: substring match for multi-word labels like "blockchain c2"
	for _, pair := range orderedLabels {
		for _, label := range normalized {
			if strings.Contains(label, pair.key) {
				return pair.category
			}
		}
	}
	// Final fallback: preserve first unknown label for precise classification
	for _, label := range normalized {
		if label != "" {
			return label
		}
	}
	return "unknown"
}

func defaultTTL(typ, category string) int64 {
	const day = int64(24 * time.Hour / time.Second)
	switch {
	case typ == "url" && category == "phishing":
		return 3 * day
	case typ == "url" && category == "malware":
		return 7 * day
	case typ == "ip" && category == "c2":
		return 14 * day
	case typ == "ip" && category == "scanner":
		return 3 * day
	case typ == "ip" && category == "botnet":
		return 30 * day
	case typ == "domain" && category == "malware":
		return 30 * day
	case typ == "cidr" && category == "scanner":
		return 3 * day
	case typ == "hash" && category == "malware":
		return 180 * day
	default:
		return 30 * day
	}
}
