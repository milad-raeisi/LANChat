package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// Group states as stored locally.
const (
	GroupActive    = "active"
	GroupLeft      = "left"
	GroupRemoved   = "removed"
	GroupDisbanded = "disbanded"
)

// GroupMember is one member of a group.
type GroupMember struct {
	PeerID      identity.PeerID
	DisplayName string
}

// Group is the local copy of a group's owner-authored state.
type Group struct {
	ID             string
	ConversationID string
	Name           string
	OwnerID        identity.PeerID
	Version        uint64
	State          string
	Members        []GroupMember
}

// HasMember reports whether id is in the member list.
func (g *Group) HasMember(id identity.PeerID) bool {
	for _, m := range g.Members {
		if m.PeerID == id {
			return true
		}
	}
	return false
}

// SaveGroup creates or replaces a group, its conversation and its members
// in one transaction.
func (s *Store) SaveGroup(ctx context.Context, g Group) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if g.ConversationID == "" {
		g.ConversationID = GroupConversationID(g.ID)
	}
	joined := g.State == GroupActive
	if _, err := tx.ExecContext(ctx, `INSERT INTO conversations (id, kind, title, joined, created_at)
		VALUES (?, 'group', ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET title = excluded.title, joined = excluded.joined`,
		g.ConversationID, g.Name, b2i(joined), ms(time.Now())); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO groups (group_id, conversation_id, name, owner_id, version, state)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (group_id) DO UPDATE SET name = excluded.name, version = excluded.version, state = excluded.state`,
		g.ID, g.ConversationID, g.Name, string(g.OwnerID), int64(g.Version), g.State); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM group_members WHERE group_id = ?", g.ID); err != nil {
		return err
	}
	for _, m := range g.Members {
		if _, err := tx.ExecContext(ctx, "INSERT INTO group_members (group_id, peer_id, display_name) VALUES (?, ?, ?)",
			g.ID, string(m.PeerID), m.DisplayName); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetGroup loads a group with its members.
func (s *Store) GetGroup(ctx context.Context, id string) (Group, error) {
	var (
		g       Group
		owner   string
		version int64
	)
	err := s.db.QueryRowContext(ctx, "SELECT group_id, conversation_id, name, owner_id, version, state FROM groups WHERE group_id = ?", id).
		Scan(&g.ID, &g.ConversationID, &g.Name, &owner, &version, &g.State)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	if err != nil {
		return Group{}, err
	}
	g.OwnerID = identity.PeerID(owner)
	g.Version = uint64(version)
	rows, err := s.db.QueryContext(ctx, "SELECT peer_id, display_name FROM group_members WHERE group_id = ? ORDER BY lower(display_name), peer_id", id)
	if err != nil {
		return Group{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var m GroupMember
		var pid string
		if err := rows.Scan(&pid, &m.DisplayName); err != nil {
			return Group{}, err
		}
		m.PeerID = identity.PeerID(pid)
		g.Members = append(g.Members, m)
	}
	return g, rows.Err()
}

// ListGroups returns every group.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT group_id FROM groups ORDER BY lower(name)")
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	out := make([]Group, 0, len(ids))
	for _, id := range ids {
		g, err := s.GetGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// CountGroups returns the number of stored groups.
func (s *Store) CountGroups(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM groups").Scan(&n)
	return n, err
}

// TransferRecord is the persisted history of a file transfer.
type TransferRecord struct {
	ID        string
	PeerID    identity.PeerID
	Direction string // "in" or "out"
	FileName  string
	Size      int64
	Path      string
	State     string
	SHA256    string
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SaveTransfer upserts a transfer record.
func (s *Store) SaveTransfer(ctx context.Context, t TransferRecord) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO transfers
		(transfer_id, peer_id, direction, file_name, size, path, state, sha256, error, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (transfer_id) DO UPDATE SET path = excluded.path, state = excluded.state,
			sha256 = excluded.sha256, error = excluded.error, updated_at = excluded.updated_at`,
		t.ID, string(t.PeerID), t.Direction, t.FileName, t.Size, t.Path, t.State, t.SHA256, t.Error,
		ms(t.CreatedAt), ms(t.UpdatedAt))
	return err
}

// ListTransfers returns the most recent transfers.
func (s *Store) ListTransfers(ctx context.Context, limit int) ([]TransferRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT transfer_id, peer_id, direction, file_name, size, path, state, sha256, error, created_at, updated_at
		FROM transfers ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TransferRecord
	for rows.Next() {
		var (
			t        TransferRecord
			peer     string
			cAt, uAt int64
		)
		if err := rows.Scan(&t.ID, &peer, &t.Direction, &t.FileName, &t.Size, &t.Path, &t.State, &t.SHA256, &t.Error, &cAt, &uAt); err != nil {
			return nil, err
		}
		t.PeerID = identity.PeerID(peer)
		t.CreatedAt, t.UpdatedAt = fromMS(cAt), fromMS(uAt)
		out = append(out, t)
	}
	return out, rows.Err()
}
