package intel

import (
	"net"
	"strings"
	"time"

	"ta_node/internal/parser"
)

type Matcher struct {
	store *Store
}

func NewMatcher(store *Store) *Matcher { return &Matcher{store: store} }

func (m *Matcher) MatchPacket(pf parser.PacketFeature) []ThreatIntel {
	now := time.Now().Unix()
	items := m.store.List()
	var hits []ThreatIntel
	for _, it := range items {
		if !it.Enabled || (it.ExpireAt > 0 && it.ExpireAt < now) {
			continue
		}
		switch strings.ToLower(it.Type) {
		case "ip":
			if matchIP(it.Value, append([]string{pf.SrcIP, pf.DstIP}, pf.DNSAnswers...)...) {
				hits = append(hits, it)
			}
		case "cidr":
			if matchCIDR(it.Value, append([]string{pf.SrcIP, pf.DstIP}, pf.DNSAnswers...)...) {
				hits = append(hits, it)
			}
		case "domain":
			if domainMatch(it.Value, pf.DNSQuery) || domainMatch(it.Value, pf.HTTPHost) {
				hits = append(hits, it)
			}
		case "url":
			if strings.EqualFold(it.Value, pf.HTTPURL) || strings.Contains(strings.ToLower(pf.HTTPURL), strings.ToLower(it.Value)) {
				hits = append(hits, it)
			}
		}
	}
	return hits
}

func matchIP(ioc string, vals ...string) bool {
	ip := net.ParseIP(ioc)
	if ip == nil {
		return false
	}
	for _, v := range vals {
		if ip.Equal(net.ParseIP(v)) {
			return true
		}
	}
	return false
}

func matchCIDR(cidr string, vals ...string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, v := range vals {
		ip := net.ParseIP(v)
		if ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func domainMatch(ioc, value string) bool {
	ioc = strings.TrimSuffix(strings.ToLower(ioc), ".")
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	return value == ioc || strings.HasSuffix(value, "."+ioc)
}
