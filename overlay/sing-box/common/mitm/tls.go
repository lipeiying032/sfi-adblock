package mitm

import (
	"crypto/tls"
	"errors"
	"strings"
)

var errNoSNI = errors.New("mitm: missing SNI")

func newServerTLSConfig(ca *CA) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		// Only offer HTTP/1.1 so clients downgrade instead of negotiating h2.
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
			if host == "" {
				return nil, errNoSNI
			}
			return ca.certificateFor(host)
		},
	}
}
