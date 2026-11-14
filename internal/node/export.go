package node

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

// Event kinds.
type EventKind int

// Event kinds published by the node.
const (
	EventPeers EventKind = iota
	EventPeerOnline
	EventPeerOffline
	EventMessage
	EventDelivery
	EventConversations
	EventPairRequest
	EventPairResult
	EventIdentityWarning
	EventFileOffer
	EventTransfer
	EventNotice
	EventNetwork
)

// Event notifies the UI of a state change.
type Event struct {
	Kind           EventKind
	PeerID         identity.PeerID
	PeerName       string
	ConversationID string
	Message        *storage.Message
	Transfer       *TransferInfo
	Text           string
	Level          string
	Code           string
	Accepted       bool
	Incoming       bool
}

// ExportedMessage is the JSON export format of one message.
type ExportedMessage struct {
	Seq            int64     `json:"seq"`
	MessageID      string    `json:"message_id"`
	ConversationID string    `json:"conversation_id"`
	SenderID       string    `json:"sender_id"`
	SenderName     string    `json:"sender_name"`
	Kind           string    `json:"kind"`
	Body           string    `json:"body"`
	SentAt         time.Time `json:"sent_at"`
	ReceivedAt     time.Time `json:"received_at"`
	Outgoing       bool      `json:"outgoing"`
	Delivery       struct {
		Pending   int `json:"pending"`
		Sent      int `json:"sent"`
		Delivered int `json:"delivered"`
		Failed    int `json:"failed"`
	} `json:"delivery"`
}

// ExportConversation writes a conversation ("" = all conversations) to path
// as "json" or "text". The file must not exist yet.
func ExportConversation(ctx context.Context, store *storage.Store, convID, path, format string) (int, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriter(f)
	n, err := writeExport(ctx, store, convID, w, format)
	if ferr := w.Flush(); err == nil {
		err = ferr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return n, err
}

func writeExport(ctx context.Context, store *storage.Store, convID string, w io.Writer, format string) (int, error) {
	var convs []string
	if convID != "" {
		convs = []string{convID}
	} else {
		list, err := store.ListConversations(ctx)
		if err != nil {
			return 0, err
		}
		for _, c := range list {
			convs = append(convs, c.ID)
		}
	}
	count := 0
	first := true
	if format == "json" {
		if _, err := io.WriteString(w, "[\n"); err != nil {
			return 0, err
		}
	}
	for _, c := range convs {
		// Page forward through the whole history.
		var all []storage.Message
		before := int64(0)
		for {
			page, err := store.Messages(ctx, c, before, 500)
			if err != nil {
				return count, err
			}
			if len(page) == 0 {
				break
			}
			all = append(page, all...)
			before = page[0].Seq
			if len(page) < 500 {
				break
			}
		}
		if format != "json" && len(all) > 0 {
			fmt.Fprintf(w, "=== %s ===\n", c)
		}
		for _, m := range all {
			count++
			if format == "json" {
				e := ExportedMessage{Seq: m.Seq, MessageID: m.ID, ConversationID: m.ConversationID, SenderID: string(m.SenderID),
					SenderName: m.SenderName, Kind: string(m.Kind), Body: m.Body, SentAt: m.SentAt.UTC(), ReceivedAt: m.ReceivedAt.UTC(), Outgoing: m.Outgoing}
				e.Delivery.Pending, e.Delivery.Sent, e.Delivery.Delivered, e.Delivery.Failed = m.Delivery.Pending, m.Delivery.Sent, m.Delivery.Delivered, m.Delivery.Failed
				b, err := json.Marshal(e)
				if err != nil {
					return count, err
				}
				if !first {
					if _, err := io.WriteString(w, ",\n"); err != nil {
						return count, err
					}
				}
				first = false
				if _, err := w.Write(b); err != nil {
					return count, err
				}
				continue
			}
			// Text exports are sanitised so that viewing them with `cat`
			// cannot inject terminal escape sequences.
			body := strings.ReplaceAll(textsafe.Text(m.Body), "\n", "\n    ")
			if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", m.SentAt.Local().Format("2006-01-02 15:04:05"), textsafe.Line(m.SenderName, 64), body); err != nil {
				return count, err
			}
		}
	}
	if format == "json" {
		if _, err := io.WriteString(w, "\n]\n"); err != nil {
			return count, err
		}
	}
	return count, nil
}

// ExportConversation exports using the node's store.
func (n *Node) ExportConversation(ctx context.Context, convID, path, format string) (int, error) {
	return ExportConversation(ctx, n.store, convID, path, format)
}
