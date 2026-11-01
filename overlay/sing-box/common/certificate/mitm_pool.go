package certificate

import (
	"crypto/x509"

	E "github.com/sagernet/sing/common/exceptions"
)

// MozillaRootPool returns the Mozilla root bundle embedded in sing-box.
// It is used by the MITM upstream client because Go cannot read the iOS
// system trust store.
func MozillaRootPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(mozillaIncludedPEM())) {
		return nil, E.New("invalid Mozilla included certificate PEM")
	}
	return pool, nil
}
