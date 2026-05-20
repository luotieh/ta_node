package fingerprint

import (
	"log"
	"regexp"
	"strings"

	"ta_node/internal/parser"
)

type Engine struct {
	rules []compiledRule
}

func New(rules []PatternRule) *Engine {
	e := &Engine{}
	for _, r := range rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			log.Printf("skip incompatible pattern rule %s: %v", r.ID, err)
			continue
		}
		e.rules = append(e.rules, compiledRule{PatternRule: r, re: re})
	}
	return e
}

func (e *Engine) Match(pf parser.PacketFeature) []FingerprintHit {
	var hits []FingerprintHit
	for _, rule := range e.rules {
		if !ruleApplies(rule.PatternRule, pf) {
			continue
		}
		target := targetPayload(rule.PatternRule, pf)
		if len(target) == 0 {
			continue
		}
		loc := rule.re.FindIndex(target)
		if len(loc) != 2 {
			continue
		}
		hits = append(hits, FingerprintHit{
			RuleID:      rule.ID,
			Type:        rule.Type,
			Name:        rule.Name,
			Version:     rule.Version,
			MatchFrom:   loc[0],
			MatchTo:     loc[1],
			HitTimeUsec: pf.PacketTimeUsec,
		})
	}
	return hits
}

func ruleApplies(rule PatternRule, pf parser.PacketFeature) bool {
	if rule.Protocol != "" && !strings.EqualFold(rule.Protocol, pf.Proto) {
		return false
	}
	if rule.Port != 0 && rule.Port != int(pf.SrcPort) && rule.Port != int(pf.DstPort) {
		return false
	}
	if rule.IsHTTP == 1 && pf.HTTPMethod == "" {
		return false
	}
	return true
}

func targetPayload(rule PatternRule, pf parser.PacketFeature) []byte {
	if rule.IsHTTP == 1 {
		switch strings.ToLower(rule.Part) {
		case "head":
			return pf.HTTPHeader
		case "body":
			return pf.HTTPBody
		case "total", "":
			return pf.Payload
		default:
			return pf.Payload
		}
	}
	return pf.Payload
}
