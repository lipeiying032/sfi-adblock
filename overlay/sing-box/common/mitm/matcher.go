package mitm

import "strings"

type hostMatcher struct {
	exact            map[string]struct{}
	suffixes         []string
	excluded         map[string]struct{}
	excludedSuffixes []string
}

func normalizePattern(pattern string) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	pattern = strings.TrimPrefix(pattern, "%append%")
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimSuffix(pattern, ".")
	return pattern
}

func buildHostMatcher(hosts, excludes []string) *hostMatcher {
	matcher := &hostMatcher{
		exact:    make(map[string]struct{}),
		excluded: make(map[string]struct{}),
	}
	for _, host := range hosts {
		host = normalizePattern(host)
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			matcher.suffixes = append(matcher.suffixes, strings.TrimPrefix(host, "*."))
			continue
		}
		matcher.exact[host] = struct{}{}
	}
	for _, host := range excludes {
		host = normalizePattern(host)
		host = strings.TrimPrefix(host, "-")
		if host == "" {
			continue
		}
		matcher.excludedSuffixes = append(matcher.excludedSuffixes, strings.TrimPrefix(host, "*."))
	}
	return matcher
}

func (m *hostMatcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.exact) + len(m.suffixes)
}

func (m *hostMatcher) Match(host string) bool {
	if m == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	if _, loaded := m.excluded[host]; loaded {
		return false
	}
	for _, suffix := range m.excludedSuffixes {
		if matchSuffix(host, suffix) {
			return false
		}
	}
	if _, loaded := m.exact[host]; loaded {
		return true
	}
	for _, suffix := range m.suffixes {
		if matchSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func matchSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// matchBlockRule reports whether a [Rule] REJECT entry covers the host.
func (c *runtimeConfig) matchBlockRule(host string) bool {
	if c == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, rule := range c.block {
		switch rule.Kind {
		case "DOMAIN":
			if host == rule.Value {
				return true
			}
		case "DOMAIN-SUFFIX":
			if matchSuffix(host, rule.Value) {
				return true
			}
		case "DOMAIN-KEYWORD":
			if strings.Contains(host, rule.Value) {
				return true
			}
		}
	}
	return false
}
