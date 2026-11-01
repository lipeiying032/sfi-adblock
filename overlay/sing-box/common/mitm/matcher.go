package mitm

import "strings"

type hostMatcher struct {
	exact            map[string]struct{}
	suffixes         []string
	globs            []string
	excludedSuffixes []string
	excludedGlobs    []string
}

// normalizePattern cleans a Shadowrocket hostname entry. Real modules mix
// %APPEND%/%INSERT% markers, wildcards, IP:port pairs and even unresolved
// {{{argument}}} placeholders in the same list.
func normalizePattern(pattern string) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	pattern = strings.TrimPrefix(pattern, "%append%")
	pattern = strings.TrimPrefix(pattern, "%insert%")
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimPrefix(pattern, "-")
	pattern = strings.TrimSpace(pattern)
	pattern = strings.TrimSuffix(pattern, ".")
	if pattern == "" || strings.Contains(pattern, "{{") || strings.Contains(pattern, "}}") {
		return ""
	}
	// "1.2.3.4:2515" style entries are matched by host only.
	if index := strings.LastIndexByte(pattern, ':'); index > 0 && !strings.Contains(pattern, "]") {
		portPart := pattern[index+1:]
		if portPart != "" && strings.Trim(portPart, "0123456789") == "" {
			pattern = pattern[:index]
		}
	}
	return pattern
}

func addHostPattern(host string, exact map[string]struct{}, suffixes *[]string, globs *[]string) {
	switch {
	case host == "":
		return
	case strings.HasPrefix(host, "*.") && !strings.Contains(host[2:], "*"):
		*suffixes = append(*suffixes, host[2:])
	case strings.Contains(host, "*"):
		*globs = append(*globs, host)
	default:
		exact[host] = struct{}{}
	}
}

func buildHostMatcher(hosts, excludes []string) *hostMatcher {
	matcher := &hostMatcher{
		exact: make(map[string]struct{}),
	}
	for _, host := range hosts {
		addHostPattern(normalizePattern(host), matcher.exact, &matcher.suffixes, &matcher.globs)
	}
	for _, host := range excludes {
		host = normalizePattern(strings.TrimPrefix(strings.TrimSpace(host), "-"))
		if host == "" {
			continue
		}
		if strings.Contains(host, "*") {
			matcher.excludedGlobs = append(matcher.excludedGlobs, host)
		} else {
			// "-host" excludes the host and all of its subdomains.
			matcher.excludedSuffixes = append(matcher.excludedSuffixes, host)
		}
	}
	return matcher
}

func (m *hostMatcher) Len() int {
	if m == nil {
		return 0
	}
	return len(m.exact) + len(m.suffixes) + len(m.globs)
}

func (m *hostMatcher) Match(host string) bool {
	if m == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	if matchAnyExact(host, m.excludedSuffixes, m.excludedGlobs) {
		return false
	}
	if _, loaded := m.exact[host]; loaded {
		return true
	}
	return matchAnyExact(host, m.suffixes, m.globs)
}

func matchAnyExact(host string, suffixes, globs []string) bool {
	for _, suffix := range suffixes {
		if matchSuffix(host, suffix) {
			return true
		}
	}
	for _, pattern := range globs {
		if matchWildcard(pattern, host) {
			return true
		}
	}
	return false
}

func matchSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// matchWildcard implements shell-style '*' matching without regexp overhead.
func matchWildcard(pattern, value string) bool {
	patternIndex, valueIndex := 0, 0
	starIndex, starValue := -1, 0
	for valueIndex < len(value) {
		if patternIndex < len(pattern) && pattern[patternIndex] == value[valueIndex] {
			patternIndex++
			valueIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			starValue = valueIndex
			patternIndex++
			continue
		}
		if starIndex >= 0 {
			patternIndex = starIndex + 1
			starValue++
			valueIndex = starValue
			continue
		}
		return false
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
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
