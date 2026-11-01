package mitm

import (
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
)

var (
	enabled atomic.Bool
	active  atomic.Bool
	caForce atomic.Bool
	caDir   atomic.Value
	modsDir atomic.Value
)

type runtimeConfig struct {
	ca        *CA
	caTrusted bool
	matcher   *hostMatcher
	rewrites  []*rewriteRule
	block     []domainRule
	modules   int
	tlsConfig *tls.Config
}

var (
	cfgAccess sync.RWMutex
	cfg       *runtimeConfig
)

// SetEnabled switches on-demand MITM on or off.
func SetEnabled(value bool) {
	enabled.Store(value)
}

// IsEnabled reports the user-facing switch state.
func IsEnabled() bool {
	return enabled.Load()
}

// IsActive reports whether interception is possible right now.
func IsActive() bool {
	return enabled.Load() && active.Load()
}

// SetCAForce allows decryption even when the CA trust check fails. It is an
// explicit user opt-in for builds where SecTrust cannot see the installed CA.
func SetCAForce(value bool) {
	caForce.Store(value)
}

// SetPaths configures where the CA and imported modules live.
func SetPaths(caPath, modulesPath string) {
	caDir.Store(caPath)
	modsDir.Store(modulesPath)
}

func storedPaths() (string, string) {
	caPath, _ := caDir.Load().(string)
	modulesPath, _ := modsDir.Load().(string)
	return caPath, modulesPath
}

func currentConfig() *runtimeConfig {
	cfgAccess.RLock()
	defer cfgAccess.RUnlock()
	return cfg
}

// Prepare reloads the CA and the enabled Shadowrocket modules.
// It is called at service start/reload, before box.New.
func Prepare() {
	startMemoryMonitor()
	caPath, modulesPath := storedPaths()
	if caPath == "" {
		active.Store(false)
		return
	}
	mitmCA, err := prepareCA(caPath)
	if err != nil {
		setLastError(err)
		active.Store(false)
		return
	}
	var prepareErr error
	modules, err := loadEnabledModules(modulesPath)
	if err != nil {
		prepareErr = err
	}
	hosts := make([]string, 0, 64)
	excludes := make([]string, 0, 16)
	rewrites := make([]*rewriteRule, 0, 32)
	block := make([]domainRule, 0, 32)
	for _, module := range modules {
		hosts = append(hosts, module.Hosts...)
		excludes = append(excludes, module.Excludes...)
		rewrites = append(rewrites, module.Rewrites...)
		block = append(block, module.Rules...)
	}
	newConfig := &runtimeConfig{
		ca:       mitmCA,
		matcher:  buildHostMatcher(hosts, excludes),
		rewrites: rewrites,
		block:    block,
		modules:  len(modules),
	}
	if mitmCA != nil {
		state := caTrustState(mitmCA.cert.Raw)
		newConfig.caTrusted = state == 1 || caForce.Load()
		if newConfig.caTrusted {
			newConfig.tlsConfig = newServerTLSConfig(mitmCA)
		} else if state == 0 {
			prepareErr = errors.New("mitm: CA is not installed or not fully trusted; decryption disabled")
		} else {
			prepareErr = errors.New("mitm: cannot verify CA trust; enable Force Decrypt to override")
		}
	}
	cfgAccess.Lock()
	cfg = newConfig
	cfgAccess.Unlock()
	setLastError(prepareErr)
	active.Store(true)
	flushStats()
}
