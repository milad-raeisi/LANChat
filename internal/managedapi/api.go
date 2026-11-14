// Package managedapi defines the HTTP+JSON API spoken between LANChat
// clients and the optional lanchat-discovery server. The server only
// coordinates discovery and presence; it never carries chat content.
//
// Transport: HTTPS over TLS 1.3. Clients authenticate with their LANChat
// identity certificate (mutual TLS); the server derives the peer ID from it.
// Clients authenticate the server by SPKI fingerprint pinning or a CA file.
package managedapi

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unicode/utf8"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// API paths.
const (
	PathAnnounce = "/v1/announce"
	PathWithdraw = "/v1/withdraw"
	PathHealth   = "/healthz"
)

// Limits applied by both sides.
const (
	MaxAddresses   = 16
	MaxPeersReturn = 1000
	MaxBodyBytes   = 64 * 1024
	MaxRespBytes   = 4 * 1024 * 1024
)

// AnnounceRequest registers or refreshes the caller's presence.
type AnnounceRequest struct {
	DisplayName     string   `json:"display_name"`
	DeviceName      string   `json:"device_name"`
	Port            int      `json:"port"`
	Addresses       []string `json:"addresses"`
	ProtocolVersion int      `json:"protocol_version"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

// Validate checks a request (server side) .
func (r *AnnounceRequest) Validate() error {
	if err := text("display_name", r.DisplayName, 256, false); err != nil {
		return err
	}
	if err := text("device_name", r.DeviceName, 256, true); err != nil {
		return err
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("invalid port %d", r.Port)
	}
	if len(r.Addresses) > MaxAddresses {
		return fmt.Errorf("too many addresses")
	}
	for _, a := range r.Addresses {
		if _, err := netip.ParseAddr(a); err != nil {
			return fmt.Errorf("invalid address %q", a)
		}
	}
	if r.ProtocolVersion < 1 || r.ProtocolVersion > 1000 {
		return fmt.Errorf("invalid protocol version")
	}
	if len(r.Capabilities) > 32 {
		return fmt.Errorf("too many capabilities")
	}
	return nil
}

// PeerEntry describes one other authorized, online peer.
type PeerEntry struct {
	PeerID          string   `json:"peer_id"`
	DisplayName     string   `json:"display_name"`
	DeviceName      string   `json:"device_name"`
	Addresses       []string `json:"addresses"` // host:port candidates, observed address first
	ProtocolVersion int      `json:"protocol_version"`
	LastSeen        int64    `json:"last_seen"` // UTC Unix milliseconds
}

// Validate checks an entry (client side; server responses are not trusted
// beyond being hints).
func (p *PeerEntry) Validate() error {
	if _, err := identity.ParsePeerID(p.PeerID); err != nil {
		return err
	}
	if err := text("display_name", p.DisplayName, 256, false); err != nil {
		return err
	}
	if err := text("device_name", p.DeviceName, 256, true); err != nil {
		return err
	}
	if len(p.Addresses) == 0 || len(p.Addresses) > MaxAddresses {
		return errors.New("invalid address list")
	}
	for _, a := range p.Addresses {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			return fmt.Errorf("invalid address %q", a)
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid address %q", a)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid address %q", a)
		}
	}
	return nil
}

// AnnounceResponse lists the other peers the caller is allowed to see.
type AnnounceResponse struct {
	Peers           []PeerEntry `json:"peers"`
	TTLSeconds      int         `json:"ttl_seconds"`
	ObservedAddress string      `json:"observed_address"`
}

// ErrorResponse is returned with non-2xx status codes.
type ErrorResponse struct {
	Error string `json:"error"`
}

func text(field, s string, max int, allowEmpty bool) error {
	if !utf8.ValidString(s) || len(s) > max || (!allowEmpty && s == "") {
		return fmt.Errorf("invalid %s", field)
	}
	return nil
}
