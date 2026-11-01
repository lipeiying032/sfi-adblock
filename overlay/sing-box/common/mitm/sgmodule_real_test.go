package mitm

import "testing"

// Mirrors the syntax used by real Shadowrocket advertising modules.
const realWorldModule = `#!name=Advertising
#!desc=real world fixture
[General]
force-http-engine-hosts = %APPEND% *.ott.cibntv.net
[URL Rewrite]
^https://a\.example\.com/(x|y) - reject-dict
^https://a\.example\.com/old https://a.example.com/new 302
(?i)\b\/ad\/ - reject
^https://a\.example\.com/h _ header
^https://a\.example\.com/z - 302
^https://a\.example\.com/q 302
[MITM]
hostname = %APPEND% *api.oray.net,103.41.167.*,*.xima*.*,1.2.3.4:2515,{{{host}}}
hostname = %INSERT% -private.example.com,*.example.com
`

func TestParseRealWorldModule(t *testing.T) {
	module := parseModule(realWorldModule)
	if module.Name != "Advertising" {
		t.Fatalf("unexpected name: %q", module.Name)
	}
	if len(module.Hosts) != 5 {
		t.Fatalf("unexpected hosts: %#v", module.Hosts)
	}
	for _, expected := range []string{"*api.oray.net", "103.41.167.*", "*.xima*.*", "1.2.3.4", "*.example.com"} {
		found := false
		for _, host := range module.Hosts {
			if host == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing host %q in %#v", expected, module.Hosts)
		}
	}
	if len(module.Excludes) != 1 || module.Excludes[0] != "private.example.com" {
		t.Fatalf("unexpected excludes: %#v", module.Excludes)
	}
	if len(module.Rewrites) != 3 {
		t.Fatalf("unexpected rewrite count: %d", len(module.Rewrites))
	}
	if module.Rewrites[0].Action != "reject-dict" || module.Rewrites[1].Action != "302" || module.Rewrites[2].Action != "reject" {
		t.Fatalf("unexpected actions: %#v", module.Rewrites)
	}
	// header + two 302 rules without a usable target + the {{{host}}} entry
	if module.Skipped != 4 {
		t.Fatalf("unexpected skipped count: %d", module.Skipped)
	}
}

func TestHostMatcherWildcards(t *testing.T) {
	matcher := buildHostMatcher([]string{
		"*api.oray.net",
		"103.41.167.*",
		"*.xima*.*",
		"*.example.com",
		"1.2.3.4",
	}, []string{"private.example.com", "*.excluded.test"})
	cases := map[string]bool{
		"api.oray.net":          true,
		"cdn.api.oray.net":      true,
		"103.41.167.42":         true,
		"103.41.168.42":         false,
		"www.xima.cn":           true,
		"a.example.com":         true,
		"example.com":           true,
		"1.2.3.4":               true,
		"private.example.com":   false,
		"x.private.example.com": false,
		"foo.excluded.test":     false,
		"other.test":            false,
	}
	for host, expected := range cases {
		if actual := matcher.Match(host); actual != expected {
			t.Fatalf("Match(%q) = %v, want %v", host, actual, expected)
		}
	}
	if matcher.Len() != 5 {
		t.Fatalf("unexpected matcher length: %d", matcher.Len())
	}
}
