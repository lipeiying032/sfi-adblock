package mitm

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caFileName     = "ca.pem"
	generateFlag   = "generate-ca"
	deleteFlag     = "delete-ca"
	leafLifetime   = 7 * 24 * time.Hour
	leafCacheLimit = 256
)

type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte

	access  sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

type leafEntry struct {
	host      string
	cert      *tls.Certificate
	expiresAt time.Time
}

func randomSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func prepareCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, caFileName)
	deleteRequest := filepath.Join(dir, deleteFlag)
	generateRequest := filepath.Join(dir, generateFlag)
	if fileExists(deleteRequest) {
		_ = keychainDelete(dir)
		_ = os.Remove(certPath)
		_ = os.Remove(deleteRequest)
	}
	keyDER, _ := keychainGet(dir)
	certPEM, certErr := os.ReadFile(certPath)
	hasKey := len(keyDER) > 0
	hasCert := certErr == nil
	if !hasKey && !hasCert && !fileExists(generateRequest) {
		// CA is only created on explicit request from the app.
		return nil, nil
	}
	needGenerate := fileExists(generateRequest) || !hasKey || !hasCert
	if needGenerate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		keyDER, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err = keychainSet(dir, keyDER); err != nil {
			return nil, err
		}
		now := time.Now()
		template := &x509.Certificate{
			SerialNumber:          randomSerial(),
			Subject:               pkix.Name{CommonName: "sfi-adblock MITM CA", Organization: []string{"sfi-adblock"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.AddDate(10, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err = os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
		_ = os.Remove(generateRequest)
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}
		return newCA(cert, key), nil
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	ecdsaKey, loaded := privateKey.(*ecdsa.PrivateKey)
	if !loaded {
		return nil, errors.New("mitm: CA key is not ECDSA")
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("mitm: invalid CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	_ = os.Remove(generateRequest)
	return newCA(cert, ecdsaKey), nil
}

func newCA(cert *x509.Certificate, key *ecdsa.PrivateKey) *CA {
	return &CA{
		cert:    cert,
		key:     key,
		der:     cert.Raw,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

func (c *CA) certificateFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\:") {
		return nil, errors.New("mitm: invalid host")
	}
	now := time.Now()
	c.access.Lock()
	if element, loaded := c.entries[host]; loaded {
		entry := element.Value.(*leafEntry)
		if now.Before(entry.expiresAt) && now.Before(c.cert.NotAfter) {
			c.lru.MoveToFront(element)
			cert := entry.cert
			c.access.Unlock()
			return cert, nil
		}
		c.lru.Remove(element)
		delete(c.entries, host)
	}
	c.access.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certificate := &tls.Certificate{
		Certificate: [][]byte{der, c.der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	c.access.Lock()
	if existing, loaded := c.entries[host]; loaded {
		c.lru.Remove(existing)
	}
	element := c.lru.PushFront(&leafEntry{host: host, cert: certificate, expiresAt: notAfter})
	c.entries[host] = element
	for c.lru.Len() > leafCacheLimit {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*leafEntry)
		c.lru.Remove(oldest)
		delete(c.entries, entry.host)
	}
	c.access.Unlock()
	return certificate, nil
}

// RequestGenerateCA asks the tunnel to create a new CA on next start/reload.
func RequestGenerateCA(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, generateFlag), []byte("1"), 0o600)
}

// RequestDeleteCA asks the tunnel to delete the CA key and certificate.
func RequestDeleteCA(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, deleteFlag), []byte("1"), 0o600)
}

type caInfo struct {
	Exists      bool   `json:"exists"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotAfter    string `json:"notAfter,omitempty"`
	Subject     string `json:"subject,omitempty"`
	PEM         string `json:"pem,omitempty"`
	Error       string `json:"error,omitempty"`
}

// CAInfoJSON describes the CA certificate for the settings page.
func CAInfoJSON(dir string) string {
	if dir == "" {
		return `{"exists":false,"error":"configuration directory is not set"}`
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, caFileName))
	if err != nil {
		encoded, _ := json.Marshal(caInfo{Exists: false})
		return string(encoded)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		encoded, _ := json.Marshal(caInfo{Exists: true, Error: "invalid PEM"})
		return string(encoded)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		encoded, _ := json.Marshal(caInfo{Exists: true, Error: err.Error()})
		return string(encoded)
	}
	fingerprint := sha256.Sum256(cert.Raw)
	info := caInfo{
		Exists:      true,
		Fingerprint: strings.ToUpper(hex.EncodeToString(fingerprint[:])),
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		Subject:     cert.Subject.CommonName,
		PEM:         string(certPEM),
	}
	encoded, _ := json.Marshal(info)
	return string(encoded)
}
