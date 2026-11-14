// Package tui implements the LANChat terminal user interface with Bubble
// Tea, Bubbles and Lip Gloss: the first-run setup wizard and the main chat
// screen. All network and database work happens in the Backend; the UI only
// issues asynchronous commands and renders state, so the event loop never
// blocks on I/O.
package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// Backend is the application core as seen by the UI. *node.Node implements
// it; tests use a fake.
type Backend interface {
	Self() node.SelfInfo
	Config() config.Config
	Events() <-chan node.Event
	Peers() []node.PeerInfo
	Peer(identity.PeerID) (node.PeerInfo, bool)
	ResolvePeer(query string) []node.PeerInfo
	NetworkStatus() node.NetworkStatus

	Conversations(ctx context.Context) ([]storage.Conversation, error)
	Messages(ctx context.Context, convID string, beforeSeq int64, limit int) ([]storage.Message, error)
	MarkRead(ctx context.Context, convID string, seq int64) error
	Search(ctx context.Context, query, convID string) ([]storage.Message, error)
	SendText(ctx context.Context, convID, body string) (storage.Message, error)
	OpenDirect(ctx context.Context, id identity.PeerID) (string, error)
	ClearHistory(ctx context.Context, convID string) (int64, error)
	RetryFailed(ctx context.Context, convID string) (int64, error)
	ExportConversation(ctx context.Context, convID, path, format string) (int, error)

	Rooms() []node.RoomInfo
	RoomMembers(name string) []node.PeerInfo
	JoinRoom(ctx context.Context, name string) (string, error)
	LeaveRoom(ctx context.Context, name string) error

	Group(ctx context.Context, groupID string) (storage.Group, error)
	CreateGroup(ctx context.Context, name string, members []identity.PeerID) (string, error)
	InviteToGroup(ctx context.Context, groupID string, peer identity.PeerID) error
	RemoveFromGroup(ctx context.Context, groupID string, peer identity.PeerID) error
	LeaveGroup(ctx context.Context, groupID string) error

	PairingInfo(id identity.PeerID) (node.PairingInfo, error)
	RequestPairing(ctx context.Context, id identity.PeerID) error
	RespondPairing(ctx context.Context, id identity.PeerID, accept bool) error
	Revoke(ctx context.Context, id identity.PeerID) error
	Ping(ctx context.Context, id identity.PeerID) (time.Duration, error)
	RefreshDiscovery()

	SendFile(ctx context.Context, peer identity.PeerID, path string) (string, error)
	RespondFile(ctx context.Context, transferID string, accept bool) error
	CancelTransfer(transferID string) error
	Transfers() []node.TransferInfo
}

var _ Backend = (*node.Node)(nil)

// RunChat runs the main chat screen until the user quits. save persists
// configuration changes made from the UI (theme, bell).
func RunChat(be Backend, save func(config.Config) error) error {
	_, err := tea.NewProgram(NewModel(be, save)).Run()
	return err
}
