package libbox

import "github.com/sagernet/sing-box/common/adblock"

// SetAdBlockEnabled toggles the built-in ad domain blocking rule.
// The value is read when the service is started or reloaded.
func SetAdBlockEnabled(enabled bool) {
	adblock.SetEnabled(enabled)
}
