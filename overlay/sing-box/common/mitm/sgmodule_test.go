package mitm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testModule = `#!name=AdBlock Test
#!desc=parser fixture
[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT
DOMAIN,exact.example.net,REJECT
IP-CIDR,10.0.0.0/8,REJECT
[URL Rewrite]
^https?://example\.com/ads/ - reject
^https?://example\.com/old https://example.com/new 302
^https?://example\.com/pixel - reject-img
[Script]
console.log("ignored")
[Map Local]
example.com data
[MITM]
hostname = %APPEND% *.example.com, example.org, -private.example.com
`

func TestParseModule(t *testing.T) {
	module := parseModule(testModule)
	if module.Name != "AdBlock Test" {
		t.Fatalf("unexpected name: %q", module.Name)
	}
	if len(module.Hosts) != 2 || module.Hosts[0] != "*.example.com" || module.Hosts[1] != "example.org" {
		t.Fatalf("unexpected hosts: %#v", module.Hosts)
	}
	if len(module.Excludes) != 1 || module.Excludes[0] != "private.example.com" {
		t.Fatalf("unexpected excludes: %#v", module.Excludes)
	}
	if len(module.Rewrites) != 3 {
		t.Fatalf("unexpected rewrites: %d", len(module.Rewrites))
	}
	if module.Rewrites[0].Action != "reject" || module.Rewrites[1].Action != "302" || module.Rewrites[2].Action != "reject-img" {
		t.Fatalf("unexpected actions: %q %q %q", module.Rewrites[0].Action, module.Rewrites[1].Action, module.Rewrites[2].Action)
	}
	if len(module.Rules) != 2 {
		t.Fatalf("unexpected rules: %d", len(module.Rules))
	}
	if module.ScriptCount != 1 {
		t.Fatalf("unexpected script count: %d", module.ScriptCount)
	}
	if len(module.IgnoredSections) != 2 {
		t.Fatalf("unexpected ignored sections: %#v", module.IgnoredSections)
	}
}

func TestHostMatcher(t *testing.T) {
	matcher := buildHostMatcher([]string{"*.example.com", "exact.org"}, []string{"private.example.com"})
	if !matcher.Match("a.example.com") {
		t.Fatal("wildcard subdomain should match")
	}
	if !matcher.Match("example.com") {
		t.Fatal("wildcard apex should match")
	}
	if !matcher.Match("exact.org") {
		t.Fatal("exact host should match")
	}
	if matcher.Match("private.example.com") || matcher.Match("x.private.example.com") {
		t.Fatal("exclusion should win")
	}
}

func TestImportListDelete(t *testing.T) {
	dir := t.TempDir()
	info, err := ImportModule(dir, testModule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info, `"rewrites":3`) {
		t.Fatalf("unexpected import info: %s", info)
	}
	listed, err := ListModulesJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed, `"name":"AdBlock Test"`) {
		t.Fatalf("unexpected module list: %s", listed)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.sgmodule"))
	if err != nil || len(files) != 1 {
		t.Fatalf("unexpected files: %#v %v", files, err)
	}
	moduleID := filepath.Base(files[0])
	if _, err = SetModuleEnabled(dir, moduleID, false); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, moduleID)); !os.IsNotExist(err) {
		t.Fatalf("enabled file should be renamed: %v", err)
	}
	if _, err = SetModuleEnabled(dir, moduleID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = DeleteModule(dir, moduleID); err != nil {
		t.Fatal(err)
	}
	rules, err := RulesJSON(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, `"hosts":[]`) {
		t.Fatalf("unexpected rules: %s", rules)
	}
}
