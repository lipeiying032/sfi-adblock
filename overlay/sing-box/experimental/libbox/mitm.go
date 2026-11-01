package libbox

import "github.com/sagernet/sing-box/common/mitm"

// SetMITMEnabled toggles on-demand TLS interception.
func SetMITMEnabled(enabled bool) {
	mitm.SetEnabled(enabled)
}

// SetMITMPaths configures the CA directory and the imported module directory.
func SetMITMPaths(caPath, modulesPath string) {
	mitm.SetPaths(caPath, modulesPath)
}

// RequestMITMCA asks the tunnel to generate a new CA on next start/reload.
func RequestMITMCA(directory string) error {
	return mitm.RequestGenerateCA(directory)
}

// RequestDeleteMITMCA asks the tunnel to delete the CA on next start/reload.
func RequestDeleteMITMCA(directory string) error {
	return mitm.RequestDeleteCA(directory)
}

// MITMCAInfo returns the CA status as JSON.
func MITMCAInfo(directory string) string {
	return mitm.CAInfoJSON(directory)
}

// MITMStats returns runtime counters as JSON.
func MITMStats() string {
	return mitm.StatsJSON()
}

// ImportMITMModule parses and stores a .sgmodule, returning its summary as JSON.
func ImportMITMModule(directory, content string) (string, error) {
	return mitm.ImportModule(directory, content)
}

// ListMITMModules returns imported modules as JSON.
func ListMITMModules(directory string) (string, error) {
	return mitm.ListModulesJSON(directory)
}

// SetMITMModuleEnabled enables or disables an imported module.
func SetMITMModuleEnabled(directory, id string, enabled bool) (string, error) {
	return mitm.SetModuleEnabled(directory, id, enabled)
}

// DeleteMITMModule removes an imported module.
func DeleteMITMModule(directory, id string) (string, error) {
	return mitm.DeleteModule(directory, id)
}

// MITMRules returns the effective MITM hosts and rewrite rules as JSON.
func MITMRules(directory string) (string, error) {
	return mitm.RulesJSON(directory)
}
