package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// ConversationKind distinguishes rooms, direct conversations and groups.
type ConversationKind string

// Conversation kinds.
const (
	KindRoom   ConversationKind = "room"
	KindDirect ConversationKind = "direct"
	KindGroup  ConversationKind = "group"
)

// GeneralRoomID is the conversation ID of the default room.
const GeneralRoomID = "room:general"

// RoomConversationID returns the conversation ID for a public room.
func RoomConversationID(name string) string { return "room:" + name }

// DirectConversationID returns the conversation ID for a direct chat.
func DirectConversationID(peer identity.PeerID) string { return "dm:" + string(peer) }

// GroupConversationID returns the conversation ID for a group.
func GroupConversationID(groupID string) string { return "group:" + groupID }

// ParseConversationID splits a conversation ID into kind and key.
func ParseConversationID(id string) (ConversationKind, string, error) {
	prefix, key, ok := strings.Cut(id, ":")
	if !ok || key == "" {
		return "", "", fmt.Errorf("invalid conversation id %q", id)
	}
	switch prefix {
	case "room":
		return KindRoom, key, nil
	case "dm":
		return KindDirect, key, nil
	case "group":
		return KindGroup, key, nil
	}
	return "", "", fmt.Errorf("invalid conversation id %q", id)
}

// Conversation is a room, direct chat or group as stored locally.
type Conversation struct {
	ID           string
	Kind         ConversationKind
	Title        string
	PeerID       identity.PeerID
	Joined       bool
	CreatedAt    time.Time
	LastReadSeq  int64
	Unread       int
	LastSeq      int64
	LastActivity time.Time
}

// EnsureConversation creates the conversation if it does not exist. If it
// exists, its title is refreshed and it is re-joined when join is true.
func (s *Store) EnsureConversation(ctx context.Context, c Conversation) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO conversations (id, kind, title, peer_id, joined, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET title = excluded.title,
			joined = CASE WHEN excluded.joined = 1 THEN 1 ELSE conversations.joined END`,
		c.ID, string(c.Kind), c.Title, string(c.PeerID), b2i(c.Joined), ms(c.CreatedAt))
	return err
}

// SetJoined marks a conversation as joined or left.
func (s *Store) SetJoined(ctx context.Context, id string, joined bool) error {
	res, err := s.db.ExecContext(ctx, "UPDATE conversations SET joined = ? WHERE id = ?", b2i(joined), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const conversationQuery = `SELECT c.id, c.kind, c.title, c.peer_id, c.joined, c.created_at, c.last_read_seq,
	(SELECT count(*) FROM messages m WHERE m.conversation_id = c.id AND m.seq > c.last_read_seq AND m.outgoing = 0 AND m.kind = 'text'),
	(SELECT coalesce(max(m.seq), 0) FROM messages m WHERE m.conversation_id = c.id),
	(SELECT coalesce(max(m.received_at), c.created_at) FROM messages m WHERE m.conversation_id = c.id)
	FROM conversations c`

func scanConversation(row interface{ Scan(...any) error }) (Conversation, error) {
	var (
		c                  Conversation
		kind, peer         string
		joined             int
		created, lastActMS int64
	)
	if err := row.Scan(&c.ID, &kind, &c.Title, &peer, &joined, &created, &c.LastReadSeq, &c.Unread, &c.LastSeq, &lastActMS); err != nil {
		return Conversation{}, err
	}
	c.Kind = ConversationKind(kind)
	c.PeerID = identity.PeerID(peer)
	c.Joined = joined != 0
	c.CreatedAt = fromMS(created)
	c.LastActivity = fromMS(lastActMS)
	return c, nil
}

// GetConversation returns one conversation with unread statistics.
func (s *Store) GetConversation(ctx context.Context, id string) (Conversation, error) {
	c, err := scanConversation(s.db.QueryRowContext(ctx, conversationQuery+" WHERE c.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Conversation{}, ErrNotFound
	}
	return c, err
}

// ListConversations returns all conversations with unread statistics.
func (s *Store) ListConversations(ctx context.Context) ([]Conversation, error) {
	rows, err := s.db.QueryContext(ctx, conversationQuery+" ORDER BY c.kind, lower(c.title)")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conversation
	for rows.Next() {
		c, err := scanConversation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// JoinedRooms returns the names of joined public rooms.
func (s *Store) JoinedRooms(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT title FROM conversations WHERE kind = 'room' AND joined = 1 ORDER BY title")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MarkRead advances the read marker of a conversation.
func (s *Store) MarkRead(ctx context.Context, id string, seq int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE conversations SET last_read_seq = max(last_read_seq, ?) WHERE id = ?", seq, id)
	return err
}

// MessageKind distinguishes chat text from local system notices.
type MessageKind string

// Message kinds.
const (
	MessageText   MessageKind = "text"
	MessageSystem MessageKind = "system"
)

// DeliveryStatus is the per-recipient state of an outgoing message.
type DeliveryStatus string

// Delivery states. Delivered is only set after the recipient acknowledged
// that it stored the message.
const (
	DeliveryPending   DeliveryStatus = "pending"
	DeliverySent      DeliveryStatus = "sent"
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryFailed    DeliveryStatus = "failed"
)

// DeliverySummary aggregates delivery rows of one outgoing message.
type DeliverySummary struct {
	Pending, Sent, Delivered, Failed int
}

// Total returns the number of recipients.
func (d DeliverySummary) Total() int { return d.Pending + d.Sent + d.Delivered + d.Failed }

// Message is a stored chat or system message.
type Message struct {
	Seq            int64
	ID             string
	ConversationID string
	SenderID       identity.PeerID
	SenderName     string
	Kind           MessageKind
	Body           string
	SentAt         time.Time
	ReceivedAt     time.Time
	Outgoing       bool
	Delivery       DeliverySummary
}

// InsertMessage stores a message and, for outgoing messages, one pending
// delivery row per recipient, atomically. If a message with the same
// (sender, message ID) already exists nothing is written and inserted is
// false; this is how duplicate deliveries are suppressed.
func (s *Store) InsertMessage(ctx context.Context, m *Message, recipients []identity.PeerID) (inserted bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if m.Kind == "" {
		m.Kind = MessageText
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO messages
		(message_id, conversation_id, sender_id, sender_name, kind, body, sent_at, received_at, outgoing)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (sender_id, message_id) DO NOTHING`,
		m.ID, m.ConversationID, string(m.SenderID), m.SenderName, string(m.Kind), m.Body,
		ms(m.SentAt), ms(m.ReceivedAt), b2i(m.Outgoing))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	m.Seq, err = res.LastInsertId()
	if err != nil {
		return false, err
	}
	now := ms(time.Now())
	for _, r := range recipients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries (message_seq, peer_id, status, created_at, updated_at)
			VALUES (?, ?, 'pending', ?, ?)`, m.Seq, string(r), now, now); err != nil {
			return false, err
		}
	}
	m.Delivery = DeliverySummary{Pending: len(recipients)}
	return true, tx.Commit()
}

const messageColumns = `m.seq, m.message_id, m.conversation_id, m.sender_id, m.sender_name, m.kind, m.body,
	m.sent_at, m.received_at, m.outgoing,
	coalesce(sum(d.status = 'pending'), 0), coalesce(sum(d.status = 'sent'), 0),
	coalesce(sum(d.status = 'delivered'), 0), coalesce(sum(d.status = 'failed'), 0)`

func scanMessages(rows *sql.Rows) ([]Message, error) {
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var (
			m              Message
			sender, kind   string
			sent, received int64
			outgoing       int
		)
		if err := rows.Scan(&m.Seq, &m.ID, &m.ConversationID, &sender, &m.SenderName, &kind, &m.Body,
			&sent, &received, &outgoing,
			&m.Delivery.Pending, &m.Delivery.Sent, &m.Delivery.Delivered, &m.Delivery.Failed); err != nil {
			return nil, err
		}
		m.SenderID = identity.PeerID(sender)
		m.Kind = MessageKind(kind)
		m.SentAt, m.ReceivedAt = fromMS(sent), fromMS(received)
		m.Outgoing = outgoing != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// Messages returns up to limit messages of a conversation with seq <
// beforeSeq (0 = latest), in ascending order.
func (s *Store) Messages(ctx context.Context, convID string, beforeSeq int64, limit int) ([]Message, error) {
	if beforeSeq <= 0 {
		beforeSeq = 1<<62 - 1
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+messageColumns+` FROM messages m
		LEFT JOIN deliveries d ON d.message_seq = m.seq
		WHERE m.conversation_id = ? AND m.seq < ?
		GROUP BY m.seq ORDER BY m.seq DESC LIMIT ?`, convID, beforeSeq, limit)
	if err != nil {
		return nil, err
	}
	out, err := scanMessages(rows)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// GetMessage returns a message by sequence number.
func (s *Store) GetMessage(ctx context.Context, seq int64) (Message, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+messageColumns+` FROM messages m
		LEFT JOIN deliveries d ON d.message_seq = m.seq WHERE m.seq = ? GROUP BY m.seq`, seq)
	if err != nil {
		return Message{}, err
	}
	out, err := scanMessages(rows)
	if err != nil {
		return Message{}, err
	}
	if len(out) == 0 {
		return Message{}, ErrNotFound
	}
	return out[0], nil
}

// Search returns text messages containing query (ASCII case-insensitive),
// newest first, optionally restricted to one conversation.
func (s *Store) Search(ctx context.Context, query, convID string, limit int) ([]Message, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+messageColumns+` FROM messages m
		LEFT JOIN deliveries d ON d.message_seq = m.seq
		WHERE m.kind = 'text' AND instr(lower(m.body), lower(?)) > 0 AND (? = '' OR m.conversation_id = ?)
		GROUP BY m.seq ORDER BY m.seq DESC LIMIT ?`, query, convID, convID, limit)
	if err != nil {
		return nil, err
	}
	return scanMessages(rows)
}

// DeleteHistory deletes all messages of one conversation (or of every
// conversation when convID is empty). Undelivered outgoing messages are
// deleted too, which also stops their retries.
func (s *Store) DeleteHistory(ctx context.Context, convID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM messages WHERE ? = '' OR conversation_id = ?", convID, convID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if convID == "" {
		_, _ = s.db.ExecContext(ctx, "UPDATE conversations SET last_read_seq = 0")
	}
	return n, nil
}

// PendingDelivery is an outgoing message still awaiting acknowledgement by
// a particular recipient.
type PendingDelivery struct {
	Seq            int64
	MessageID      string
	ConversationID string
	Body           string
	SentAt         time.Time
	PeerID         identity.PeerID
	Status         DeliveryStatus
	Attempts       int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PendingFor returns undelivered messages for a recipient in send order.
func (s *Store) PendingFor(ctx context.Context, peer identity.PeerID, limit int) ([]PendingDelivery, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.message_seq, m.message_id, m.conversation_id, m.body, m.sent_at,
		d.status, d.attempts, d.created_at, d.updated_at
		FROM deliveries d JOIN messages m ON m.seq = d.message_seq
		WHERE d.peer_id = ? AND d.status IN ('pending', 'sent')
		ORDER BY d.message_seq LIMIT ?`, string(peer), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingDelivery
	for rows.Next() {
		var (
			p                       PendingDelivery
			status                  string
			sent, creation, updated int64
		)
		if err := rows.Scan(&p.Seq, &p.MessageID, &p.ConversationID, &p.Body, &sent, &status, &p.Attempts, &creation, &updated); err != nil {
			return nil, err
		}
		p.PeerID = peer
		p.Status = DeliveryStatus(status)
		p.SentAt, p.CreatedAt, p.UpdatedAt = fromMS(sent), fromMS(creation), fromMS(updated)
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountQueued returns the number of undelivered messages for a recipient.
func (s *Store) CountQueued(ctx context.Context, peer identity.PeerID) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM deliveries WHERE peer_id = ? AND status IN ('pending', 'sent')", string(peer)).Scan(&n)
	return n, err
}

// MarkDelivery sets the status of one delivery row. Moving to "sent"
// increments the attempt counter. A delivered row is never downgraded.
func (s *Store) MarkDelivery(ctx context.Context, seq int64, peer identity.PeerID, status DeliveryStatus, errText string) error {
	inc := 0
	if status == DeliverySent {
		inc = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE deliveries SET status = ?, error = ?, updated_at = ?, attempts = attempts + ?
		WHERE message_seq = ? AND peer_id = ? AND status != 'delivered'`,
		string(status), errText, ms(time.Now()), inc, seq, string(peer))
	return err
}

// AckResult describes the effect of an acknowledgement.
type AckResult struct {
	Seq            int64
	ConversationID string
	Changed        bool
}

// ApplyAck records a recipient's acknowledgement of one of our messages.
// Only the delivery row belonging to that recipient can change, so a peer
// cannot acknowledge on behalf of another.
func (s *Store) ApplyAck(ctx context.Context, self, peer identity.PeerID, messageID string, status DeliveryStatus, reason string) (AckResult, error) {
	var r AckResult
	err := s.db.QueryRowContext(ctx, "SELECT seq, conversation_id FROM messages WHERE sender_id = ? AND message_id = ?",
		string(self), messageID).Scan(&r.Seq, &r.ConversationID)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE deliveries SET status = ?, error = ?, updated_at = ?
		WHERE message_seq = ? AND peer_id = ? AND status != 'delivered'`,
		string(status), reason, ms(time.Now()), r.Seq, string(peer))
	if err != nil {
		return r, err
	}
	n, _ := res.RowsAffected()
	r.Changed = n > 0
	return r, nil
}

// ExpireDeliveries marks undelivered rows older than cutoff, or with too
// many attempts, as failed. Messages are kept; only their state changes.
// It returns the affected conversation IDs.
func (s *Store) ExpireDeliveries(ctx context.Context, cutoff time.Time, maxAttempts int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT m.conversation_id FROM deliveries d JOIN messages m ON m.seq = d.message_seq
		WHERE d.status IN ('pending', 'sent') AND (d.created_at < ? OR d.attempts >= ?)`, ms(cutoff), maxAttempts)
	if err != nil {
		return nil, err
	}
	var convs []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return nil, err
		}
		convs = append(convs, c)
	}
	rows.Close()
	if len(convs) == 0 {
		return nil, nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE deliveries SET status = 'failed', updated_at = ?,
		error = CASE WHEN created_at < ? THEN 'expired before the recipient came online' ELSE 'too many delivery attempts' END
		WHERE status IN ('pending', 'sent') AND (created_at < ? OR attempts >= ?)`,
		ms(time.Now()), ms(cutoff), ms(cutoff), maxAttempts)
	return convs, err
}

// RetryFailed re-queues failed deliveries of a conversation.
func (s *Store) RetryFailed(ctx context.Context, convID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE deliveries SET status = 'pending', attempts = 0, error = '', created_at = ?, updated_at = ?
		WHERE status = 'failed' AND message_seq IN (SELECT seq FROM messages WHERE conversation_id = ?)`,
		ms(time.Now()), ms(time.Now()), convID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FailPendingFor marks every undelivered message for a recipient as failed
// (used when trust in that peer is revoked). It returns the affected
// conversation IDs.
func (s *Store) FailPendingFor(ctx context.Context, peer identity.PeerID, reason string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT m.conversation_id FROM deliveries d JOIN messages m ON m.seq = d.message_seq
		WHERE d.peer_id = ? AND d.status IN ('pending', 'sent')`, string(peer))
	if err != nil {
		return nil, err
	}
	var convs []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return nil, err
		}
		convs = append(convs, c)
	}
	rows.Close()
	_, err = s.db.ExecContext(ctx, `UPDATE deliveries SET status = 'failed', error = ?, updated_at = ?
		WHERE peer_id = ? AND status IN ('pending', 'sent')`, reason, ms(time.Now()), string(peer))
	return convs, err
}
