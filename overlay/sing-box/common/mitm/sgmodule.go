package mitm

import (
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type rewriteRule struct {
	Pattern     *regexp.Regexp
	Replacement string
	Action      string
	Module      string
}

type domainRule struct {
	Kind   string
	Value  string
	Action string
	Module string
}

// Module is a parsed Shadowrocket .sgmodule file.
type Module struct {
	ID              string
	Name            string
	Description     string
	Hosts           []string
	Excludes        []string
	Rewrites        []*rewriteRule
	Rules           []domainRule
	ScriptCount     int
	IgnoredSections []string
	Enabled         bool
	Path            string
}

type moduleInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Hosts       int      `json:"hosts"`
	Excludes    int      `json:"excludes"`
	Rewrites    int      `json:"rewrites"`
	Rules       int      `json:"rules"`
	Scripts     int      `json:"scripts"`
	Ignored     []string `json:"ignored,omitempty"`
}

type rewriteView struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement,omitempty"`
	Action      string `json:"action"`
	Module      string `json:"module"`
}

type ruleView struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
	Module string `json:"module"`
}

type rulesView struct {
	Hosts    []string      `json:"hosts"`
	Excludes []string      `json:"excludes"`
	Rewrites []rewriteView `json:"rewrites"`
	Rules    []ruleView    `json:"rules"`
	Modules  []string      `json:"modules"`
}

func (m *Module) info() moduleInfo {
	info := moduleInfo{
		ID:          m.ID,
		Name:        m.Name,
		Description: m.Description,
		Enabled:     m.Enabled,
		Hosts:       len(m.Hosts),
		Excludes:    len(m.Excludes),
		Rewrites:    len(m.Rewrites),
		Rules:       len(m.Rules),
		Scripts:     m.ScriptCount,
		Ignored:     m.IgnoredSections,
	}
	return info
}

func parseModule(content string) *Module {
	module := &Module{}
	ignored := make(map[string]struct{})
	section := ""
	for _, rawLine := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "#!name=") {
			module.Name = strings.TrimSpace(line[len("#!name="):])
			continue
		}
		if strings.HasPrefix(lower, "#!desc=") {
			module.Description = strings.TrimSpace(line[len("#!desc="):])
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		switch section {
		case "mitm":
			key, value, found := strings.Cut(line, "=")
			if !found || !strings.EqualFold(strings.TrimSpace(key), "hostname") {
				continue
			}
			for _, host := range strings.Split(value, ",") {
				host = strings.TrimSpace(host)
				host = strings.TrimPrefix(strings.TrimPrefix(host, "%APPEND%"), "%append%")
				host = strings.TrimSpace(host)
				if host == "" {
					continue
				}
				if strings.HasPrefix(host, "-") {
					module.Excludes = append(module.Excludes, strings.TrimPrefix(host, "-"))
					continue
				}
				module.Hosts = append(module.Hosts, host)
			}
		case "url rewrite":
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pattern := strings.Trim(fields[0], "\"'")
			replacement := strings.Trim(fields[1], "\"'")
			action := ""
			if len(fields) >= 3 {
				action = strings.ToLower(fields[2])
			}
			if action == "" {
				if replacement == "-" {
					action = "reject"
				} else if strings.HasPrefix(replacement, "http") {
					action = "302"
				} else {
					action = "reject"
				}
			}
			switch action {
			case "reject", "reject-200", "reject-img", "reject-dict", "reject-array", "302", "307":
			default:
				continue
			}
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			module.Rewrites = append(module.Rewrites, &rewriteRule{
				Pattern:     compiled,
				Replacement: replacement,
				Action:      action,
			})
		case "rule":
			fields := strings.Split(line, ",")
			if len(fields) < 3 {
				continue
			}
			kind := strings.ToUpper(strings.TrimSpace(fields[0]))
			value := strings.TrimSpace(fields[1])
			action := strings.ToUpper(strings.TrimSpace(fields[2]))
			if value == "" || !strings.HasPrefix(action, "REJECT") {
				continue
			}
			switch kind {
			case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
				module.Rules = append(module.Rules, domainRule{Kind: kind, Value: strings.ToLower(value), Action: "REJECT"})
			default:
				ignored[section] = struct{}{}
			}
		case "script":
			module.ScriptCount++
		case "":
		default:
			ignored[section] = struct{}{}
		}
	}
	for name := range ignored {
		module.IgnoredSections = append(module.IgnoredSections, name)
	}
	if module.Name == "" {
		module.Name = "Imported Module"
	}
	return module
}

func sanitizeID(name string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(name) {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			builder.WriteRune(char)
		} else if builder.Len() > 0 {
			builder.WriteByte('-')
		}
		if builder.Len() >= 40 {
			break
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		result = "module"
	}
	return result
}

func moduleFiles(dir string, enabledOnly bool) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	if enabledOnly {
		return filepath.Glob(filepath.Join(dir, "*.sgmodule"))
	}
	enabled, err := filepath.Glob(filepath.Join(dir, "*.sgmodule"))
	if err != nil {
		return nil, err
	}
	disabled, err := filepath.Glob(filepath.Join(dir, "*.sgmodule.disabled"))
	if err != nil {
		return nil, err
	}
	return append(enabled, disabled...), nil
}

func loadModuleFile(path string) (*Module, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	module := parseModule(string(content))
	module.ID = filepath.Base(path)
	module.Path = path
	module.Enabled = !strings.HasSuffix(path, ".disabled")
	return module, nil
}

func loadEnabledModules(dir string) ([]*Module, error) {
	files, err := moduleFiles(dir, true)
	if err != nil {
		return nil, err
	}
	var modules []*Module
	for _, file := range files {
		module, err := loadModuleFile(file)
		if err != nil {
			continue
		}
		modules = append(modules, module)
	}
	return modules, nil
}

// ImportModule parses a .sgmodule and stores it in the modules directory.
func ImportModule(dir, content string) (string, error) {
	module := parseModule(content)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id := sanitizeID(module.Name) + "-" + strconvFormatHex(crc32.ChecksumIEEE([]byte(content))) + ".sgmodule"
	path := filepath.Join(dir, id)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	module.ID = id
	module.Path = path
	module.Enabled = true
	current := currentConfig()
	if current != nil {
		// A re-import should be visible without restarting the tunnel.
		Prepare()
	}
	encoded, err := json.Marshal(module.info())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func strconvFormatHex(value uint32) string {
	const digits = "0123456789abcdef"
	buffer := make([]byte, 8)
	for index := 7; index >= 0; index-- {
		buffer[index] = digits[value&0xf]
		value >>= 4
	}
	return string(buffer)
}

// ListModulesJSON lists enabled and disabled modules for the UI.
func ListModulesJSON(dir string) (string, error) {
	files, err := moduleFiles(dir, false)
	if err != nil {
		return "", err
	}
	infos := make([]moduleInfo, 0, len(files))
	for _, file := range files {
		module, err := loadModuleFile(file)
		if err != nil {
			continue
		}
		infos = append(infos, module.info())
	}
	encoded, err := json.Marshal(infos)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// SetModuleEnabled renames a module between the enabled and disabled suffixes.
func SetModuleEnabled(dir, id string, enabled bool) (string, error) {
	id = filepath.Base(id)
	enabledPath := filepath.Join(dir, strings.TrimSuffix(id, ".disabled"))
	disabledPath := enabledPath + ".disabled"
	if enabled {
		if _, err := os.Stat(disabledPath); err == nil {
			if err := os.Rename(disabledPath, enabledPath); err != nil {
				return "", err
			}
		}
	} else {
		if _, err := os.Stat(enabledPath); err == nil {
			if err := os.Rename(enabledPath, disabledPath); err != nil {
				return "", err
			}
		}
	}
	if IsEnabled() {
		Prepare()
	}
	return ListModulesJSON(dir)
}

// DeleteModule removes a module file.
func DeleteModule(dir, id string) (string, error) {
	id = strings.TrimSuffix(filepath.Base(id), ".disabled")
	for _, path := range []string{filepath.Join(dir, id), filepath.Join(dir, id+".disabled")} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	if IsEnabled() {
		Prepare()
	}
	return ListModulesJSON(dir)
}

// RulesJSON returns the currently effective MITM hosts and rewrite rules.
func RulesJSON(dir string) (string, error) {
	modules, err := loadEnabledModules(dir)
	if err != nil {
		return "", err
	}
	view := rulesView{Hosts: []string{}, Excludes: []string{}, Rewrites: []rewriteView{}, Rules: []ruleView{}, Modules: []string{}}
	for _, module := range modules {
		view.Modules = append(view.Modules, module.Name)
		view.Hosts = append(view.Hosts, module.Hosts...)
		view.Excludes = append(view.Excludes, module.Excludes...)
		for _, rule := range module.Rewrites {
			view.Rewrites = append(view.Rewrites, rewriteView{Pattern: rule.Pattern.String(), Replacement: rule.Replacement, Action: rule.Action, Module: module.Name})
		}
		for _, rule := range module.Rules {
			view.Rules = append(view.Rules, ruleView{Kind: rule.Kind, Value: rule.Value, Action: rule.Action, Module: module.Name})
		}
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
