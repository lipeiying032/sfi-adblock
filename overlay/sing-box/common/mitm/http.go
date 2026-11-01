package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/certificate"
	N "github.com/sagernet/sing/common/network"
)

const (
	handshakeTimeout = 5 * time.Second
	upstreamTimeout  = 10 * time.Second
	idleTimeout      = 90 * time.Second
)

var transparentGIF, _ = base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

type upstreamConn struct {
	conn   *tls.Conn
	reader *bufio.Reader
}

func (u *upstreamConn) close() {
	if u != nil && u.conn != nil {
		_ = u.conn.Close()
	}
}

var (
	rootPoolOnce sync.Once
	rootPool     *x509.CertPool
)

func upstreamRootPool() *x509.CertPool {
	rootPoolOnce.Do(func() {
		// On iOS Go cannot read the system trust store; use the Mozilla bundle
		// that sing-box already embeds.
		pool, err := certificate.MozillaRootPool()
		if err == nil {
			rootPool = pool
		}
	})
	return rootPool
}

func stripHopByHop(header http.Header) {
	for _, name := range hopHeaders {
		header.Del(name)
	}
}

func dialUpstream(ctx context.Context, dialer N.Dialer, metadata *adapter.InboundContext, host string) (*upstreamConn, error) {
	rawConn, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    upstreamRootPool(),
	})
	handshakeContext, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	if err = tlsConn.HandshakeContext(handshakeContext); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return &upstreamConn{conn: tlsConn, reader: bufio.NewReaderSize(tlsConn, 8192)}, nil
}

func writeResponse(writer io.Writer, request *http.Request, status int, contentType string, body []byte) error {
	response := &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       request,
	}
	if contentType != "" {
		response.Header.Set("Content-Type", contentType)
	}
	return response.Write(writer)
}

func writeBadGateway(writer io.Writer, request *http.Request) {
	_ = writeResponse(writer, request, http.StatusBadGateway, "text/plain; charset=utf-8", []byte("sfi-adblock: upstream handshake failed\n"))
}

func (c *runtimeConfig) matchRewrite(fullURL string) *rewriteRule {
	for _, rule := range c.rewrites {
		if rule.Pattern.MatchString(fullURL) {
			return rule
		}
	}
	return nil
}

func applyRewrite(writer io.Writer, request *http.Request, rule *rewriteRule, fullURL string) error {
	switch rule.Action {
	case "reject":
		return writeResponse(writer, request, http.StatusForbidden, "text/plain; charset=utf-8", []byte("Blocked by sfi-adblock\n"))
	case "reject-200":
		return writeResponse(writer, request, http.StatusOK, "text/plain; charset=utf-8", nil)
	case "reject-img":
		return writeResponse(writer, request, http.StatusOK, "image/gif", transparentGIF)
	case "reject-dict":
		return writeResponse(writer, request, http.StatusOK, "application/json; charset=utf-8", []byte("{}"))
	case "reject-array":
		return writeResponse(writer, request, http.StatusOK, "application/json; charset=utf-8", []byte("[]"))
	case "302", "307":
		status := http.StatusFound
		if rule.Action == "307" {
			status = http.StatusTemporaryRedirect
		}
		target := rule.Pattern.ReplaceAllString(fullURL, rule.Replacement)
		if target == "" || target == "-" {
			target = fullURL
		}
		response := &http.Response{
			StatusCode:    status,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(nil)),
			ContentLength: 0,
			Close:         true,
			Request:       request,
		}
		response.Header.Set("Location", target)
		return response.Write(writer)
	}
	return nil
}

func blindRelay(ctx context.Context, client *tls.Conn, reader *bufio.Reader, metadata *adapter.InboundContext, host string, dialer N.Dialer) {
	rawConn, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		return
	}
	upstream := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    upstreamRootPool(),
	})
	handshakeContext, cancel := context.WithTimeout(ctx, upstreamTimeout)
	err = upstream.HandshakeContext(handshakeContext)
	cancel()
	if err != nil {
		_ = rawConn.Close()
		return
	}
	metrics.fallbacks.Add(1)
	go func() {
		_, _ = io.Copy(upstream, io.MultiReader(reader, client))
		_ = upstream.CloseWrite()
	}()
	_, _ = io.Copy(client, upstream)
	_ = upstream.Close()
}

func serveMITM(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, host string, dialer N.Dialer, onClose N.CloseHandlerFunc) {
	defer func() { <-connSlots }()
	defer flushStats()
	defer func() {
		if recovered := recover(); recovered != nil {
			metrics.fallbacks.Add(1)
			setLastError(fmt.Errorf("mitm: panic: %v", recovered))
		}
	}()
	handshakeHeld := true
	releaseHandshake := func() {
		if handshakeHeld {
			<-handshakeSlots
			handshakeHeld = false
		}
	}
	defer releaseHandshake()

	metrics.intercepted.Add(1)
	metrics.activeConns.Add(1)
	defer metrics.activeConns.Add(-1)

	var tlsConn *tls.Conn
	var finalErr error
	defer func() {
		if tlsConn != nil {
			// Bound the close_notify write so a vanished client cannot stall the
			// connection lifecycle callback below.
			_ = tlsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = tlsConn.Close()
		}
		if onClose != nil {
			onClose(finalErr)
		}
	}()

	current := currentConfig()
	if current == nil || current.ca == nil || current.tlsConfig == nil {
		return
	}
	tlsConn = tls.Server(conn, current.tlsConfig)
	handshakeContext, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tlsConn.HandshakeContext(handshakeContext)
	cancel()
	releaseHandshake()
	if err != nil {
		metrics.fallbacks.Add(1)
		markBypass(host)
		finalErr = err
		_ = tlsConn.Close()
		return
	}
	if !strings.EqualFold(tlsConn.ConnectionState().ServerName, host) {
		metrics.fallbacks.Add(1)
		markBypass(host)
		finalErr = errNoSNI
		_ = tlsConn.Close()
		return
	}

	reader := bufio.NewReaderSize(tlsConn, 8192)
	var upstream *upstreamConn
	defer func() { upstream.close() }()

	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(idleTimeout))
		request, readErr := http.ReadRequest(reader)
		_ = tlsConn.SetReadDeadline(time.Time{})
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
				finalErr = nil
				return
			}
			// Unknown protocol on 443: relay the decrypted bytes as-is.
			blindRelay(ctx, tlsConn, reader, metadata, host, dialer)
			finalErr = readErr
			return
		}
		fullURL := "https://" + host + request.URL.RequestURI()
		if rewrite := current.matchRewrite(fullURL); rewrite != nil {
			metrics.rewritten.Add(1)
			if err = applyRewrite(tlsConn, request, rewrite, fullURL); err != nil {
				finalErr = err
			}
			return
		}
		if upstream == nil {
			upstream, err = dialUpstream(ctx, dialer, metadata, host)
			if err != nil {
				metrics.fallbacks.Add(1)
				// Do not keep breaking this host next time; let it pass through.
				markBypass(host)
				writeBadGateway(tlsConn, request)
				finalErr = err
				return
			}
		}
		clientClose := request.Close
		request.RequestURI = ""
		request.Close = false
		stripHopByHop(request.Header)
		if err = request.Write(upstream.conn); err != nil {
			finalErr = err
			return
		}
		response, responseErr := http.ReadResponse(upstream.reader, request)
		if responseErr != nil {
			finalErr = responseErr
			return
		}
		if err = response.Write(tlsConn); err != nil {
			_ = response.Body.Close()
			finalErr = err
			return
		}
		_ = response.Body.Close()
		if clientClose || response.Close {
			return
		}
	}
}
