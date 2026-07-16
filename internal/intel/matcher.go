package intel

import (
	"net"
	"strings"
	"sync"
	"time"

	"ta_node/internal/parser"
)

type Matcher struct {
	store     *Store
	mu        sync.RWMutex
	ipSet     map[string][]ThreatIntel
	cidrs     []CIDRIntel
	domainMap map[string][]ThreatIntel
	urlMap    map[string][]ThreatIntel
	urlList   []ThreatIntel
	version   int64
}

func NewMatcher(store *Store) *Matcher { return &Matcher{store: store} }

type CIDRIntel struct {
	Network *net.IPNet
	Intel   ThreatIntel
}

func (m *Matcher) MatchPacket(pf parser.PacketFeature) []ThreatIntel {
	m.ensureIndex()
	now := time.Now().Unix()
	var hits []ThreatIntel
	seen := map[string]bool{}
	addHit := func(it ThreatIntel) {
		key := it.ID
		if key == "" {
			key = it.Type + ":" + it.Value
		}
		if !seen[key] && active(it, now) {
			seen[key] = true
			hits = append(hits, it)
		}
	}
	ips := append([]string{pf.SrcIP, pf.DstIP}, pf.DNSAnswers...)
	m.mu.RLock()
	for _, ip := range ips {
		for _, it := range m.ipSet[canonicalIP(ip)] {
			addHit(it)
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		for _, cidr := range m.cidrs {
			if cidr.Network.Contains(parsed) {
				addHit(cidr.Intel)
			}
		}
	}
	for _, it := range m.matchDomainLocked(pf.DNSQuery) {
		addHit(it)
	}
	for _, it := range m.matchDomainLocked(pf.HTTPHost) {
		addHit(it)
	}
	for _, it := range m.matchDomainLocked(pf.SNI) {
		addHit(it)
	}
	// DNS answers may include CNAME targets (domains, not IPs); match those
	// against domain IOCs so malicious CNAME chains are caught.
	for _, ans := range pf.DNSAnswers {
		if net.ParseIP(ans) != nil {
			continue
		}
		for _, it := range m.matchDomainLocked(ans) {
			addHit(it)
		}
	}
	if pf.HTTPURL != "" {
		lowerURL := strings.ToLower(pf.HTTPURL)
		for _, it := range m.urlMap[lowerURL] {
			addHit(it)
		}
		for _, it := range m.urlList {
			if strings.Contains(lowerURL, strings.ToLower(it.Value)) {
				addHit(it)
			}
		}
	}
	m.mu.RUnlock()
	return hits
}

func (m *Matcher) ensureIndex() {
	version := m.store.Version()
	m.mu.RLock()
	current := m.version
	m.mu.RUnlock()
	if current == version {
		return
	}
	m.rebuildIndex(version)
}

func (m *Matcher) rebuildIndex(version int64) {
	items := m.store.List()
	ipSet := map[string][]ThreatIntel{}
	var cidrs []CIDRIntel
	domainMap := map[string][]ThreatIntel{}
	urlMap := map[string][]ThreatIntel{}
	var urlList []ThreatIntel
	for _, it := range items {
		switch strings.ToLower(it.Type) {
		case "ip":
			if ip := canonicalIP(it.Value); ip != "" {
				ipSet[ip] = append(ipSet[ip], it)
			}
		case "cidr":
			if _, network, err := net.ParseCIDR(it.Value); err == nil {
				cidrs = append(cidrs, CIDRIntel{Network: network, Intel: it})
			}
		case "domain":
			domain := canonicalDomain(it.Value)
			if domain != "" {
				domainMap[domain] = append(domainMap[domain], it)
			}
		case "url":
			value := strings.ToLower(strings.TrimSpace(it.Value))
			if value == "" {
				continue
			}
			urlMap[value] = append(urlMap[value], it)
			urlList = append(urlList, it)
		}
	}
	m.mu.Lock()
	m.ipSet = ipSet
	m.cidrs = cidrs
	m.domainMap = domainMap
	m.urlMap = urlMap
	m.urlList = urlList
	m.version = version
	m.mu.Unlock()
}

func (m *Matcher) matchDomainLocked(value string) []ThreatIntel {
	value = canonicalDomain(value)
	if value == "" {
		return nil
	}
	var hits []ThreatIntel
	for domain, items := range m.domainMap {
		if value == domain || strings.HasSuffix(value, "."+domain) {
			for _, it := range items {
				hits = append(hits, it)
			}
		}
	}
	return hits
}

func active(it ThreatIntel, now int64) bool {
	return it.Enabled && (it.ExpireAt == 0 || it.ExpireAt >= now)
}

func canonicalIP(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func canonicalDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
