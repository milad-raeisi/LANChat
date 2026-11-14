package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// Message types. The type namespace is versioned together with the protocol.
const (
	TypeHello       = "hello"
	TypeError       = "error"
	TypePing        = "ping"
	TypePong        = "pong"
	TypePresence    = "presence"
	TypePairRequest = "pair.request"
	TypePairNonce   = "pair.nonce"
	TypePairReveal  = "pair.reveal"
	TypePairAccept  = "pair.accept"
	TypePairReject  = "pair.reject"
	TypePairRevoke  = "pair.revoke"
	TypeChat        = "chat.message"
	TypeAck         = "chat.ack"
	TypeGroupUpdate = "group.update"
	TypeGroupLeave  = "group.leave"
	TypeGroupSync   = "group.sync"
	TypeFileOffer   = "file.offer"
	TypeFileAccept  = "file.accept"
	TypeFileReject  = "file.reject"
	TypeFileCancel  = "file.cancel"
	TypeFileDone    = "file.done"
	TypeFileResult  = "file.result"
)

// Limits on untrusted fields.
const (
	MaxBodyBytes    = 64 * 1024
	MaxNameBytes    = 256
	MaxRooms        = 32
	MaxGroupMembers = 64
	MaxGroups       = 256
	MaxFileName     = 255
	MaxReasonBytes  = 256
)

// Conversation kinds carried by chat messages.
const (
	ConvRoom   = "room"
	ConvDirect = "direct"
	ConvGroup  = "group"
)

// Error codes sent in error messages.
const (
	CodeIncompatibleVersion = "incompatible_version"
	CodeIdentityMismatch    = "identity_mismatch"
	CodeProtocolViolation   = "protocol_violation"
	CodeNotTrusted          = "not_trusted"
	CodeRateLimited         = "rate_limited"
	CodeTooManyConnections  = "too_many_connections"
	CodeShuttingDown        = "shutting_down"
	CodeDuplicateSession    = "duplicate_session"
)

// ErrInvalid wraps every semantic validation failure.
var ErrInvalid = errors.New("invalid message")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// NewID returns a random 128-bit identifier as 32 lowercase hex characters.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// ValidID reports whether s is a 32-character lowercase hex identifier.
func ValidID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ValidRoomName reports whether s is a valid public room name: 1–32
// characters of lowercase ASCII letters, digits, '-' and '_', starting with
// a letter or digit.
func ValidRoomName(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// NormalizeRoomName lowercases and trims a user-entered room name and strips
// a leading '#'.
func NormalizeRoomName(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "#"))
}

func validText(field, s string, max int, allowEmpty bool) error {
	if !utf8.ValidString(s) {
		return invalid("%s is not valid UTF-8", field)
	}
	if len(s) > max {
		return invalid("%s exceeds %d bytes", field, max)
	}
	if !allowEmpty && strings.TrimSpace(s) == "" {
		return invalid("%s is empty", field)
	}
	return nil
}

func validPeerID(field, s string) error {
	if _, err := identity.ParsePeerID(s); err != nil {
		return invalid("%s is not a valid peer id", field)
	}
	return nil
}

// Validator is implemented by every message body.
type Validator interface {
	Validate() error
}

// DecodeBody unmarshals an envelope body into T and validates it.
func DecodeBody[T any, PT interface {
	*T
	Validator
}](env *Envelope) (*T, error) {
	var v T
	if len(env.Body) == 0 {
		return nil, invalid("%s has no body", env.Type)
	}
	if err := json.Unmarshal(env.Body, &v); err != nil {
		return nil, invalid("%s body: %v", env.Type, err)
	}
	if err := PT(&v).Validate(); err != nil {
		return nil, err
	}
	return &v, nil
}

// Hello is the first message each side sends after the TLS handshake.
type Hello struct {
	ProtocolVersion int      `json:"protocol_version"`
	MinVersion      int      `json:"min_version"`
	PeerID          string   `json:"peer_id"`
	DisplayName     string   `json:"display_name"`
	DeviceName      string   `json:"device_name"`
	ListenPort      int      `json:"listen_port"`
	App             string   `json:"app"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

// Validate implements Validator.
func (h *Hello) Validate() error {
	if h.ProtocolVersion < 1 || h.MinVersion < 1 || h.MinVersion > h.ProtocolVersion {
		return invalid("hello version range %d..%d", h.MinVersion, h.ProtocolVersion)
	}
	if err := validPeerID("hello.peer_id", h.PeerID); err != nil {
		return err
	}
	if err := validText("hello.display_name", h.DisplayName, MaxNameBytes, false); err != nil {
		return err
	}
	if err := validText("hello.device_name", h.DeviceName, MaxNameBytes, true); err != nil {
		return err
	}
	if h.ListenPort < 0 || h.ListenPort > 65535 {
		return invalid("hello.listen_port %d", h.ListenPort)
	}
	if err := validText("hello.app", h.App, 64, true); err != nil {
		return err
	}
	if len(h.Capabilities) > 32 {
		return invalid("too many capabilities")
	}
	for _, c := range h.Capabilities {
		if err := validText("capability", c, 32, false); err != nil {
			return err
		}
	}
	return nil
}

// Negotiate returns the highest protocol version supported by both ranges.
func Negotiate(localMin, localMax, remoteMin, remoteMax int) (int, bool) {
	v := localMax
	if remoteMax < v {
		v = remoteMax
	}
	lo := localMin
	if remoteMin > lo {
		lo = remoteMin
	}
	if v < lo {
		return 0, false
	}
	return v, true
}

// ErrorMsg reports a protocol-level error before the sender closes or
// rejects something.
type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Validate implements Validator.
func (e *ErrorMsg) Validate() error {
	if err := validText("error.code", e.Code, 64, false); err != nil {
		return err
	}
	return validText("error.message", e.Message, MaxReasonBytes, true)
}

// Ping is a keepalive / round-trip probe. The receiver answers with Pong
// carrying the same nonce.
type Ping struct {
	Nonce string `json:"nonce"`
}

// Validate implements Validator.
func (p *Ping) Validate() error {
	if !ValidID(p.Nonce) {
		return invalid("ping nonce")
	}
	return nil
}

// Presence announces the sender's current profile and joined public rooms.
type Presence struct {
	DisplayName string   `json:"display_name"`
	DeviceName  string   `json:"device_name"`
	Status      string   `json:"status"`
	Rooms       []string `json:"rooms"`
}

// Validate implements Validator.
func (p *Presence) Validate() error {
	if err := validText("presence.display_name", p.DisplayName, MaxNameBytes, false); err != nil {
		return err
	}
	if err := validText("presence.device_name", p.DeviceName, MaxNameBytes, true); err != nil {
		return err
	}
	switch p.Status {
	case "online", "away", "busy":
	default:
		return invalid("presence.status %q", truncate(p.Status, 16))
	}
	if len(p.Rooms) > MaxRooms {
		return invalid("presence lists more than %d rooms", MaxRooms)
	}
	for _, r := range p.Rooms {
		if !ValidRoomName(r) {
			return invalid("presence room %q", truncate(r, 40))
		}
	}
	return nil
}

// PairRequest starts pairing. Commit is SHA-256 over the initiator's secret
// pairing nonce (see identity.PairingCommit); the nonce is revealed only
// after the responder has sent its own nonce, so neither side can choose
// its nonce to steer the verification code (commit-then-reveal).
type PairRequest struct {
	DisplayName string `json:"display_name"`
	Commit      string `json:"commit"`
}

// Validate implements Validator.
func (p *PairRequest) Validate() error {
	if !validHex(p.Commit, 64) {
		return invalid("pair.commit")
	}
	return validText("pair.display_name", p.DisplayName, MaxNameBytes, false)
}

// PairNonce carries a pairing nonce: the responder's nonce (pair.nonce) or
// the initiator's revealed nonce (pair.reveal).
type PairNonce struct {
	Nonce string `json:"nonce"`
}

// Validate implements Validator.
func (p *PairNonce) Validate() error {
	if !validHex(p.Nonce, 64) {
		return invalid("pair.nonce")
	}
	return nil
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// PairResponse answers a PairRequest (pair.accept / pair.reject) or informs
// the peer that trust was revoked (pair.revoke).
type PairResponse struct {
	Reason string `json:"reason,omitempty"`
}

// Validate implements Validator.
func (p *PairResponse) Validate() error {
	return validText("pair.reason", p.Reason, MaxReasonBytes, true)
}

// ChatMessage carries one chat message.
type ChatMessage struct {
	MessageID string `json:"message_id"`
	Kind      string `json:"kind"`
	Room      string `json:"room,omitempty"`
	GroupID   string `json:"group_id,omitempty"`
	Body      string `json:"body"`
	SentAt    int64  `json:"sent_at"`
}

// Validate implements Validator.
func (m *ChatMessage) Validate() error {
	if !ValidID(m.MessageID) {
		return invalid("chat.message_id")
	}
	switch m.Kind {
	case ConvRoom:
		if !ValidRoomName(m.Room) || m.GroupID != "" {
			return invalid("chat room %q", truncate(m.Room, 40))
		}
	case ConvDirect:
		if m.Room != "" || m.GroupID != "" {
			return invalid("direct chat must not name a room or group")
		}
	case ConvGroup:
		if !ValidID(m.GroupID) || m.Room != "" {
			return invalid("chat group id")
		}
	default:
		return invalid("chat kind %q", truncate(m.Kind, 16))
	}
	if err := validText("chat.body", m.Body, MaxBodyBytes, false); err != nil {
		return err
	}
	if m.SentAt < 0 {
		return invalid("chat.sent_at")
	}
	return nil
}

// Ack acknowledges receipt of a chat message.
type Ack struct {
	MessageID string `json:"message_id"`
	// Status is "delivered" (stored by the recipient) or "rejected".
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Ack statuses.
const (
	AckDelivered = "delivered"
	AckRejected  = "rejected"
)

// Validate implements Validator.
func (a *Ack) Validate() error {
	if !ValidID(a.MessageID) {
		return invalid("ack message_id")
	}
	if a.Status != AckDelivered && a.Status != AckRejected {
		return invalid("ack status")
	}
	return validText("ack.reason", a.Reason, MaxReasonBytes, true)
}

// GroupMember is one member in a group snapshot.
type GroupMember struct {
	PeerID      string `json:"peer_id"`
	DisplayName string `json:"display_name"`
}

// GroupUpdate is an owner-authored snapshot of a group's state.
type GroupUpdate struct {
	GroupID string `json:"group_id"`
	// Salt binds the group ID to the owner's key: GroupID must equal
	// rooms.DeriveGroupID(owner key, Salt), so no one else can claim it.
	Salt    string        `json:"salt"`
	Name    string        `json:"name"`
	OwnerID string        `json:"owner_id"`
	Version uint64        `json:"version"`
	State   string        `json:"state"`
	Members []GroupMember `json:"members"`
}

// Group states.
const (
	GroupActive    = "active"
	GroupDisbanded = "disbanded"
)

// Validate implements Validator.
func (g *GroupUpdate) Validate() error {
	if !ValidID(g.GroupID) {
		return invalid("group id")
	}
	if !validHex(g.Salt, 32) {
		return invalid("group salt")
	}
	if err := validText("group.name", g.Name, 128, false); err != nil {
		return err
	}
	if err := validPeerID("group.owner_id", g.OwnerID); err != nil {
		return err
	}
	if g.Version == 0 {
		return invalid("group version must be positive")
	}
	if g.State != GroupActive && g.State != GroupDisbanded {
		return invalid("group state")
	}
	if len(g.Members) > MaxGroupMembers {
		return invalid("group has more than %d members", MaxGroupMembers)
	}
	seen := make(map[string]bool, len(g.Members))
	ownerListed := false
	for _, m := range g.Members {
		if err := validPeerID("group member", m.PeerID); err != nil {
			return err
		}
		if seen[m.PeerID] {
			return invalid("duplicate group member")
		}
		seen[m.PeerID] = true
		if m.PeerID == g.OwnerID {
			ownerListed = true
		}
		if err := validText("group member name", m.DisplayName, MaxNameBytes, true); err != nil {
			return err
		}
	}
	if g.State == GroupActive && !ownerListed {
		return invalid("group owner must be a member")
	}
	return nil
}

// GroupLeave tells the owner that the sender left a group.
type GroupLeave struct {
	GroupID string `json:"group_id"`
}

// Validate implements Validator.
func (g *GroupLeave) Validate() error {
	if !ValidID(g.GroupID) {
		return invalid("group id")
	}
	return nil
}

// GroupSyncEntry describes the sender's view of one group.
type GroupSyncEntry struct {
	GroupID string `json:"group_id"`
	Version uint64 `json:"version"`
	// Status is "member" or "left".
	Status string `json:"status"`
}

// GroupSync is sent after a session is established so the group owner can
// push newer snapshots and learn about members that left while offline.
type GroupSync struct {
	Groups []GroupSyncEntry `json:"groups"`
}

// Validate implements Validator.
func (g *GroupSync) Validate() error {
	if len(g.Groups) > MaxGroups {
		return invalid("group sync lists too many groups")
	}
	for _, e := range g.Groups {
		if !ValidID(e.GroupID) {
			return invalid("group sync id")
		}
		if e.Status != "member" && e.Status != "left" {
			return invalid("group sync status")
		}
	}
	return nil
}

// FileOffer proposes a file transfer to the receiver.
type FileOffer struct {
	TransferID string `json:"transfer_id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
}

// Validate implements Validator.
func (f *FileOffer) Validate() error {
	if !ValidID(f.TransferID) {
		return invalid("transfer id")
	}
	if err := validText("file.name", f.Name, MaxFileName, false); err != nil {
		return err
	}
	if f.Size < 0 {
		return invalid("file size")
	}
	return nil
}

// FileControl is used by file.accept, file.reject and file.cancel.
type FileControl struct {
	TransferID string `json:"transfer_id"`
	Reason     string `json:"reason,omitempty"`
}

// Validate implements Validator.
func (f *FileControl) Validate() error {
	if !ValidID(f.TransferID) {
		return invalid("transfer id")
	}
	return validText("file.reason", f.Reason, MaxReasonBytes, true)
}

// FileDone is sent by the sender after the last chunk.
type FileDone struct {
	TransferID string `json:"transfer_id"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}

// Validate implements Validator.
func (f *FileDone) Validate() error {
	if !ValidID(f.TransferID) {
		return invalid("transfer id")
	}
	if f.Size < 0 {
		return invalid("file size")
	}
	if len(f.SHA256) != 64 {
		return invalid("file hash")
	}
	if _, err := hex.DecodeString(f.SHA256); err != nil {
		return invalid("file hash")
	}
	return nil
}

// FileResult is the receiver's verdict after verifying the file.
type FileResult struct {
	TransferID string `json:"transfer_id"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// Validate implements Validator.
func (f *FileResult) Validate() error {
	if !ValidID(f.TransferID) {
		return invalid("transfer id")
	}
	return validText("file.error", f.Error, MaxReasonBytes, true)
}
