package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// TrustState is the local trust decision about a peer.
type TrustState string

// Trust states.
const (
	TrustUnknown TrustState = "unknown"
	TrustTrusted TrustState = "trusted"
	TrustRevoked TrustState = "revoked"
)

// Peer is a remote identity that has completed at least one authenticated
// connection.
type Peer struct {
	ID          identity.PeerID
	PublicKey   []byte // DER SubjectPublicKeyInfo
	DisplayName string
	DeviceName  string
	Trust       TrustState
	Verified    bool // the pairing code was confirmed by the user
	FirstSeen   time.Time
	LastSeen    time.Time
	TrustedAt   time.Time
	LastAddress string
}

// ErrKeyMismatch indicates a stored peer ID is associated with a different
// public key, which can only happen if the database was tampered with.
var ErrKeyMismatch = errors.New("stored public key does not match peer id")

// PeerSeen records an authenticated connection with a peer.
type PeerSeen struct {
	ID          identity.PeerID
	PublicKey   []byte
	DisplayName string
	DeviceName  string
	Address     string
	At          time.Time
}

// RecordPeerSeen inserts the peer or refreshes its names, address and
// last-seen time. It never changes trust.
func (s *Store) RecordPeerSeen(ctx context.Context, p PeerSeen) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existing []byte
	err = tx.QueryRowContext(ctx, "SELECT public_key FROM peers WHERE peer_id = ?", string(p.ID)).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO peers
			(peer_id, public_key, display_name, device_name, trust, first_seen, last_seen, last_address)
			VALUES (?, ?, ?, ?, 'unknown', ?, ?, ?)`,
			string(p.ID), p.PublicKey, p.DisplayName, p.DeviceName, ms(p.At), ms(p.At), p.Address)
	case err != nil:
		return err
	default:
		if !bytes.Equal(existing, p.PublicKey) {
			return fmt.Errorf("%w: %s", ErrKeyMismatch, p.ID)
		}
		_, err = tx.ExecContext(ctx, `UPDATE peers SET display_name = ?, device_name = ?, last_seen = ?,
			last_address = CASE WHEN ? = '' THEN last_address ELSE ? END WHERE peer_id = ?`,
			p.DisplayName, p.DeviceName, ms(p.At), p.Address, p.Address, string(p.ID))
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// TouchPeer updates the last-seen time.
func (s *Store) TouchPeer(ctx context.Context, id identity.PeerID, at time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE peers SET last_seen = ? WHERE peer_id = ?", ms(at), string(id))
	return err
}

const peerColumns = `peer_id, public_key, display_name, device_name, trust, verified, first_seen, last_seen, trusted_at, last_address`

func scanPeer(row interface{ Scan(...any) error }) (Peer, error) {
	var (
		p                         Peer
		id, trust                 string
		verified                  int
		first, last, trustedAtInt int64
	)
	if err := row.Scan(&id, &p.PublicKey, &p.DisplayName, &p.DeviceName, &trust, &verified, &first, &last, &trustedAtInt, &p.LastAddress); err != nil {
		return Peer{}, err
	}
	p.ID = identity.PeerID(id)
	p.Trust = TrustState(trust)
	p.Verified = verified != 0
	p.FirstSeen, p.LastSeen, p.TrustedAt = fromMS(first), fromMS(last), fromMS(trustedAtInt)
	return p, nil
}

// GetPeer returns one peer or ErrNotFound.
func (s *Store) GetPeer(ctx context.Context, id identity.PeerID) (Peer, error) {
	p, err := scanPeer(s.db.QueryRowContext(ctx, "SELECT "+peerColumns+" FROM peers WHERE peer_id = ?", string(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	return p, err
}

// ListPeers returns every known peer ordered by display name.
func (s *Store) ListPeers(ctx context.Context) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+peerColumns+" FROM peers ORDER BY lower(display_name), peer_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetTrust changes the trust state of a known peer.
func (s *Store) SetTrust(ctx context.Context, id identity.PeerID, trust TrustState, verified bool, at time.Time) error {
	var trustedAt int64
	if trust == TrustTrusted {
		trustedAt = ms(at)
	}
	res, err := s.db.ExecContext(ctx, "UPDATE peers SET trust = ?, verified = ?, trusted_at = ? WHERE peer_id = ?",
		string(trust), b2i(verified), trustedAt, string(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TrustedPeersNamed returns trusted peers with the given display and device
// name. Used to detect a new identity impersonating a known person.
func (s *Store) TrustedPeersNamed(ctx context.Context, displayName, deviceName string) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+peerColumns+` FROM peers
		WHERE trust = 'trusted' AND lower(display_name) = lower(?) AND lower(device_name) = lower(?)`, displayName, deviceName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
