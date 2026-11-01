package mitm

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "sfi-mitm test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return newCA(cert, key)
}

func setTestConfig(t *testing.T, current *runtimeConfig) {
	t.Helper()
	cfgAccess.Lock()
	previous := cfg
	cfg = current
	cfgAccess.Unlock()
	t.Cleanup(func() {
		cfgAccess.Lock()
		cfg = previous
		cfgAccess.Unlock()
	})
}

func holdMITMSlots(t *testing.T) {
	t.Helper()
	connSlots <- struct{}{}
	handshakeSlots <- struct{}{}
	t.Cleanup(func() {
		// serveMITM releases both slots on exit; if it bailed early, drain here.
		select {
		case <-connSlots:
		default:
		}
		select {
		case <-handshakeSlots:
		default:
		}
	})
}

func echoMetadata(host string) *adapter.InboundContext {
	return &adapter.InboundContext{
		Domain:      host,
		Destination: M.ParseSocksaddrHostPort(host, 443),
	}
}

func TestLeafCertificateVerifies(t *testing.T) {
	ca := newTestCA(t)
	leaf, err := ca.certificateFor("ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err = leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "ads.example.com", Roots: pool}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	cached, err := ca.certificateFor("ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cached != leaf {
		t.Fatal("expected certificate cache hit")
	}
}

func runRewriteTest(t *testing.T, rule *rewriteRule, request string, assert func(*testing.T, *http.Response)) {
	t.Helper()
	ca := newTestCA(t)
	host := "ads.example.com"
	setTestConfig(t, &runtimeConfig{
		ca:        ca,
		matcher:   buildHostMatcher([]string{host}, nil),
		rewrites:  []*rewriteRule{rule},
		tlsConfig: newServerTLSConfig(ca),
	})
	clientConn, serverConn := net.Pipe()
	holdMITMSlots(t)
	closed := make(chan error, 1)
	go serveMITM(context.Background(), serverConn, echoMetadata(host), host, nil, func(err error) {
		closed <- err
	})
	client := tls.Client(clientConn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	defer func() { _ = client.Close() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = body
	assert(t, response)
	// Closing the raw pipe (instead of the TLS conn) unblocks the server's
	// close_notify write immediately; on TCP that write never blocks.
	_ = clientConn.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was not called")
	}
}

func TestServeMITMReject(t *testing.T) {
	rule := &rewriteRule{
		Pattern: regexp.MustCompile(`^https://ads\.example\.com/ad\.js`),
		Action:  "reject",
	}
	runRewriteTest(t, rule, "GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nConnection: close\r\n\r\n", func(t *testing.T, response *http.Response) {
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("unexpected status: %d", response.StatusCode)
		}
	})
}

func TestServeMITMRedirect(t *testing.T) {
	rule := &rewriteRule{
		Pattern:     regexp.MustCompile(`^https://ads\.example\.com/ad\.js`),
		Replacement: "https://cdn.example.com/blank",
		Action:      "302",
	}
	runRewriteTest(t, rule, "GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nConnection: close\r\n\r\n", func(t *testing.T, response *http.Response) {
		if response.StatusCode != http.StatusFound {
			t.Fatalf("unexpected status: %d", response.StatusCode)
		}
		if location := response.Header.Get("Location"); location != "https://cdn.example.com/blank" {
			t.Fatalf("unexpected location: %q", location)
		}
	})
}

func enableTestMITM(t *testing.T) {
	t.Helper()
	SetEnabled(true)
	active.Store(true)
	t.Cleanup(func() {
		SetEnabled(false)
		active.Store(false)
	})
}

func TestTryInterceptRuleBlock(t *testing.T) {
	ca := newTestCA(t)
	enableTestMITM(t)
	setTestConfig(t, &runtimeConfig{
		ca:      ca,
		matcher: buildHostMatcher([]string{"ads.example.com"}, nil),
		block:   []domainRule{{Kind: "DOMAIN-SUFFIX", Value: "ads.example.com", Action: "REJECT"}},
	})
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	closed := make(chan error, 1)
	conn, intercepted := TryIntercept(context.Background(), serverConn, echoMetadata("cdn.ads.example.com"), nil, func(err error) {
		closed <- err
	})
	if !intercepted {
		t.Fatal("expected rule block interception")
	}
	if conn == nil {
		t.Fatal("expected connection")
	}
	select {
	case err := <-closed:
		if err == nil || !strings.Contains(err.Error(), "blocked by imported rule") {
			t.Fatalf("unexpected close error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onClose was not called")
	}
}

func TestTryInterceptPassThrough(t *testing.T) {
	ca := newTestCA(t)
	setTestConfig(t, &runtimeConfig{
		ca:        ca,
		matcher:   buildHostMatcher([]string{"ads.example.com"}, nil),
		tlsConfig: newServerTLSConfig(ca),
	})
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()
	if _, intercepted := TryIntercept(context.Background(), serverConn, echoMetadata("other.example.com"), nil, nil); intercepted {
		t.Fatal("host outside the MITM list must pass through")
	}
}

func TestTryInterceptDisabledWithoutTLSConfig(t *testing.T) {
	ca := newTestCA(t)
	setTestConfig(t, &runtimeConfig{
		ca:      ca,
		matcher: buildHostMatcher([]string{"ads.example.com"}, nil),
	})
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()
	if _, intercepted := TryIntercept(context.Background(), serverConn, echoMetadata("ads.example.com"), nil, nil); intercepted {
		t.Fatal("interception requires a confirmed/loaded TLS config")
	}
}
