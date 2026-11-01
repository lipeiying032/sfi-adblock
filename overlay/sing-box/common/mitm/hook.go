package mitm

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	sBufio "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

var errBlockedByRule = errors.New("blocked by imported rule")

var (
	connSlots      = make(chan struct{}, 16)
	handshakeSlots = make(chan struct{}, 4)

	bypassAccess sync.Mutex
	bypassUntil  = make(map[string]time.Time)
)

func acquireSlots() bool {
	select {
	case connSlots <- struct{}{}:
	default:
		return false
	}
	select {
	case handshakeSlots <- struct{}{}:
	default:
		<-connSlots
		return false
	}
	return true
}

func markBypass(host string) {
	if host == "" {
		return
	}
	bypassAccess.Lock()
	bypassUntil[host] = time.Now().Add(10 * time.Minute)
	bypassAccess.Unlock()
}

func isBypassed(host string) bool {
	bypassAccess.Lock()
	defer bypassAccess.Unlock()
	until, loaded := bypassUntil[host]
	if !loaded {
		return false
	}
	if time.Now().After(until) {
		delete(bypassUntil, host)
		return false
	}
	return true
}

// TryIntercept decides whether the connection should be decrypted.
// It returns the (possibly buffered) connection and whether it took ownership.
func TryIntercept(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, dialer N.Dialer, onClose N.CloseHandlerFunc) (net.Conn, bool) {
	if !IsActive() {
		return conn, false
	}
	current := currentConfig()
	if current == nil || current.matcher == nil {
		return conn, false
	}
	port := metadata.Destination.Port
	if port != 443 && port != 8443 {
		return conn, false
	}
	host := strings.ToLower(strings.TrimSuffix(metadata.Domain, "."))
	if host == "" {
		buffer := buf.NewPacket()
		sniffErr := sniff.PeekStream(ctx, metadata, conn, nil, buffer, C.ReadPayloadTimeout, sniff.TLSClientHello)
		if buffer.Len() > 0 {
			conn = sBufio.NewCachedConn(conn, buffer)
		} else {
			buffer.Release()
		}
		if sniffErr != nil {
			return conn, false
		}
		host = strings.ToLower(strings.TrimSuffix(metadata.Domain, "."))
	}
	if host == "" || isBypassed(host) {
		return conn, false
	}
	if current.matchBlockRule(host) {
		metrics.blocked.Add(1)
		if onClose != nil {
			onClose(errBlockedByRule)
		}
		_ = conn.Close()
		return conn, true
	}
	if !current.matcher.Match(host) || current.ca == nil || current.tlsConfig == nil {
		return conn, false
	}
	if !acquireSlots() {
		return conn, false
	}
	serveMITM(ctx, conn, metadata, host, dialer, onClose)
	return conn, true
}
