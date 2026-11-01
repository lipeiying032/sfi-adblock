package mitm

import (
	"encoding/json"
	"sync/atomic"
)

type counters struct {
	intercepted atomic.Int64
	rewritten   atomic.Int64
	blocked     atomic.Int64
	fallbacks   atomic.Int64
	activeConns atomic.Int64
}

var metrics counters

type statsSnapshot struct {
	Enabled     bool   `json:"enabled"`
	Active      bool   `json:"active"`
	CAReady     bool   `json:"caReady"`
	Modules     int    `json:"modules"`
	Hosts       int    `json:"hosts"`
	Rewrites    int    `json:"rewrites"`
	Rules       int    `json:"rules"`
	Intercepted int64  `json:"intercepted"`
	Rewritten   int64  `json:"rewritten"`
	Blocked     int64  `json:"blocked"`
	Fallbacks   int64  `json:"fallbacks"`
	ActiveConns int64  `json:"activeConnections"`
	LastError   string `json:"lastError,omitempty"`
}

// StatsJSON is consumed by the app settings page.
func StatsJSON() string {
	current := currentConfig()
	snapshot := statsSnapshot{
		Enabled:     enabled.Load(),
		Active:      active.Load(),
		Intercepted: metrics.intercepted.Load(),
		Rewritten:   metrics.rewritten.Load(),
		Blocked:     metrics.blocked.Load(),
		Fallbacks:   metrics.fallbacks.Load(),
		ActiveConns: metrics.activeConns.Load(),
		LastError:   lastError(),
	}
	if current != nil {
		snapshot.CAReady = current.ca != nil
		snapshot.Modules = current.modules
		if current.matcher != nil {
			snapshot.Hosts = current.matcher.Len()
		}
		snapshot.Rewrites = len(current.rewrites)
		snapshot.Rules = len(current.block)
	}
	content, err := json.Marshal(snapshot)
	if err != nil {
		return "{}"
	}
	return string(content)
}

var lastErrorValue atomic.Value

func setLastError(err error) {
	if err == nil {
		lastErrorValue.Store("")
		return
	}
	lastErrorValue.Store(err.Error())
}

func lastError() string {
	value, _ := lastErrorValue.Load().(string)
	return value
}
