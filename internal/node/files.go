package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
	"github.com/milad-raeisi/LANChat/internal/transfer"
)

// Transfer states.
const (
	TransferOffered      = "offered"      // outgoing: waiting for the recipient
	TransferIncoming     = "incoming"     // incoming: waiting for the local user
	TransferTransferring = "transferring" // data is flowing
	TransferVerifying    = "verifying"    // sender waits for the integrity verdict
	TransferCompleted    = "completed"
	TransferRejected     = "rejected"
	TransferCancelled    = "cancelled"
	TransferFailed       = "failed"
)

const (
	offerTimeout       = 5 * time.Minute
	resultTimeout      = 2 * time.Minute
	stallTimeout       = 2 * time.Minute
	maxOutgoingActive  = 8
	maxIncomingActive  = 16
	maxIncomingPerPeer = 3
)

// TransferInfo is a snapshot of a file transfer.
type TransferInfo struct {
	ID          string
	PeerID      identity.PeerID
	PeerName    string
	Outgoing    bool
	Name        string
	Size        int64
	Transferred int64
	State       string
	Path        string
	Error       string
	StartedAt   time.Time
	UpdatedAt   time.Time
}

// Done reports whether the transfer reached a final state.
func (t TransferInfo) Done() bool {
	switch t.State {
	case TransferCompleted, TransferRejected, TransferCancelled, TransferFailed:
		return true
	}
	return false
}

type transferState struct {
	mu       sync.Mutex
	info     TransferInfo
	session  *transport.Session
	file     *os.File
	incoming *transfer.IncomingFile
	accept   chan bool
	result   chan protocol.FileResult
	cancel   context.CancelFunc
	lastEmit time.Time
	node     *Node
	done     chan struct{} // closed when the transfer reaches a final state
}

func (t *transferState) snapshot() TransferInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.info
}

// finish moves the transfer to a final state exactly once.
func (t *transferState) finish(state, errText, path string) bool {
	t.mu.Lock()
	if t.info.Done() {
		t.mu.Unlock()
		return false
	}
	t.info.State, t.info.Error, t.info.UpdatedAt = state, errText, time.Now()
	if path != "" {
		t.info.Path = path
	}
	if t.cancel != nil {
		t.cancel()
	}
	if t.done != nil {
		close(t.done)
	}
	if t.file != nil {
		_ = t.file.Close()
		t.file = nil
	}
	if t.incoming != nil && state != TransferCompleted {
		t.incoming.Abort()
		t.incoming = nil
	}
	info := t.info
	t.mu.Unlock()
	n := t.node
	n.log.Info("file transfer finished", "transfer", info.ID, "peer", string(info.PeerID), "outgoing", info.Outgoing,
		"state", info.State, "bytes", info.Transferred, "error", info.Error)
	_ = n.store.SaveTransfer(context.Background(), storage.TransferRecord{
		ID: info.ID, PeerID: info.PeerID, Direction: dir(info.Outgoing), FileName: info.Name, Size: info.Size,
		Path: info.Path, State: info.State, Error: info.Error, CreatedAt: info.StartedAt,
	})
	n.emit(Event{Kind: EventTransfer, PeerID: info.PeerID, PeerName: info.PeerName, Transfer: &info})
	n.transferSystemMessage(info)
	return true
}

func (t *transferState) abort(reason string) {
	t.mu.Lock()
	s := t.session
	id := t.info.ID
	t.mu.Unlock()
	if t.finish(TransferCancelled, reason, "") && s != nil {
		_ = s.Send(protocol.TypeFileCancel, protocol.FileControl{TransferID: id, Reason: reason})
	}
}

func dir(out bool) string {
	if out {
		return "out"
	}
	return "in"
}

func (n *Node) transferSystemMessage(info TransferInfo) {
	convID := storage.DirectConversationID(info.PeerID)
	ctx := context.Background()
	if err := n.store.EnsureConversation(ctx, storage.Conversation{ID: convID, Kind: storage.KindDirect, Title: info.PeerName, PeerID: info.PeerID, Joined: true}); err != nil {
		return
	}
	size := HumanSize(info.Size)
	var text string
	switch {
	case info.State == TransferCompleted && info.Outgoing:
		text = fmt.Sprintf("File sent: %s (%s). The recipient verified its SHA-256 checksum.", info.Name, size)
	case info.State == TransferCompleted:
		text = fmt.Sprintf("File received: %s (%s), checksum verified. Saved to %s", info.Name, size, info.Path)
	case info.State == TransferRejected:
		text = fmt.Sprintf("File transfer of %s was declined. %s", info.Name, info.Error)
	case info.State == TransferCancelled:
		text = fmt.Sprintf("File transfer of %s was cancelled: %s", info.Name, info.Error)
	default:
		text = fmt.Sprintf("File transfer of %s failed: %s", info.Name, info.Error)
	}
	n.systemMessage(ctx, convID, text)
}

// HumanSize formats a byte count.
func HumanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for v := b / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Transfers returns current and recent transfers, newest first.
func (n *Node) Transfers() []TransferInfo {
	n.mu.Lock()
	list := make([]*transferState, 0, len(n.transfers))
	for _, t := range n.transfers {
		list = append(list, t)
	}
	n.mu.Unlock()
	out := make([]TransferInfo, 0, len(list))
	for _, t := range list {
		out = append(out, t.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// activeTransfers counts unfinished transfers in one direction, optionally
// only those with a given peer.
func (n *Node) activeTransfers(outgoing bool, peer identity.PeerID) int {
	n.mu.Lock()
	list := make([]*transferState, 0, len(n.transfers))
	for _, t := range n.transfers {
		list = append(list, t)
	}
	n.mu.Unlock()
	c := 0
	for _, t := range list {
		info := t.snapshot()
		if !info.Done() && info.Outgoing == outgoing && (peer == "" || info.PeerID == peer) {
			c++
		}
	}
	return c
}

func (n *Node) transferByID(id string) *transferState {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.transfers[id]
}

func (n *Node) addTransfer(t *transferState) {
	n.mu.Lock()
	n.transfers[t.info.ID] = t
	// Bound memory: forget the oldest finished transfers.
	if len(n.transfers) > 200 {
		var oldest *transferState
		for _, x := range n.transfers {
			if x.snapshot().Done() && (oldest == nil || x.info.StartedAt.Before(oldest.info.StartedAt)) {
				oldest = x
			}
		}
		if oldest != nil {
			delete(n.transfers, oldest.info.ID)
		}
	}
	n.mu.Unlock()
}

// SendFile offers a local file to a paired, connected peer. The transfer
// starts only after the recipient accepts it.
func (n *Node) SendFile(ctx context.Context, peer identity.PeerID, path string) (string, error) {
	if !n.isTrusted(peer) {
		return "", ErrNotPaired
	}
	s := n.trustedSession(peer)
	if s == nil {
		return "", ErrNotConnected
	}
	if n.activeTransfers(true, "") >= maxOutgoingActive {
		return "", fmt.Errorf("too many active outgoing transfers (limit %d)", maxOutgoingActive)
	}
	f, name, size, err := transfer.OpenOutgoing(path)
	if err != nil {
		return "", err
	}
	tctx, cancel := context.WithCancel(n.ctx)
	t := &transferState{
		node:    n,
		info:    TransferInfo{ID: protocol.NewID(), PeerID: peer, PeerName: n.peerName(peer), Outgoing: true, Name: name, Size: size, State: TransferOffered, StartedAt: time.Now(), UpdatedAt: time.Now()},
		session: s, file: f, accept: make(chan bool, 1), result: make(chan protocol.FileResult, 1), cancel: cancel,
		done: make(chan struct{}),
	}
	n.addTransfer(t)
	_ = n.store.SaveTransfer(ctx, storage.TransferRecord{ID: t.info.ID, PeerID: peer, Direction: "out", FileName: name, Size: size, Path: f.Name(), State: TransferOffered})
	if err := s.Send(protocol.TypeFileOffer, protocol.FileOffer{TransferID: t.info.ID, Name: name, Size: size}); err != nil {
		t.finish(TransferFailed, err.Error(), "")
		return "", err
	}
	info := t.snapshot()
	n.emit(Event{Kind: EventTransfer, PeerID: peer, Transfer: &info})
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.runOutgoing(tctx, t)
	}()
	return t.info.ID, nil
}

func (n *Node) runOutgoing(ctx context.Context, t *transferState) {
	select {
	case ok := <-t.accept:
		if !ok {
			return // finish already called by the reject handler
		}
	case <-time.After(offerTimeout):
		t.abort("the recipient did not answer in time")
		return
	case <-ctx.Done():
		return
	}
	t.mu.Lock()
	if t.info.Done() {
		t.mu.Unlock()
		return
	}
	t.info.State = TransferTransferring
	f, s, id := t.file, t.session, t.info.ID
	t.mu.Unlock()
	n.emitProgress(t, true)

	h := sha256.New()
	buf := make([]byte, protocol.ChunkSize)
	var offset uint64
	for {
		nr, rerr := f.Read(buf)
		if nr > 0 {
			h.Write(buf[:nr])
			frame, err := protocol.EncodeChunk(id, offset, buf[:nr])
			if err != nil {
				t.finish(TransferFailed, err.Error(), "")
				return
			}
			if err := s.SendBulk(ctx, frame); err != nil {
				if ctx.Err() == nil {
					t.finish(TransferFailed, "connection lost", "")
				}
				return
			}
			offset += uint64(nr)
			t.mu.Lock()
			t.info.Transferred = int64(offset)
			t.mu.Unlock()
			n.emitProgress(t, false)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.abort("cannot read local file: " + rerr.Error())
			return
		}
	}
	if int64(offset) != t.info.Size {
		t.abort("the file changed size while being sent")
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	t.mu.Lock()
	t.info.State = TransferVerifying
	t.mu.Unlock()
	n.emitProgress(t, true)
	// file.done travels on the bulk queue so it cannot overtake the chunks.
	if err := s.SendBulkEnvelope(ctx, protocol.TypeFileDone, protocol.FileDone{TransferID: id, Size: int64(offset), SHA256: sum}); err != nil {
		t.finish(TransferFailed, "connection lost", "")
		return
	}
	select {
	case r := <-t.result:
		if r.OK {
			t.finish(TransferCompleted, "", "")
		} else {
			t.finish(TransferFailed, "recipient reported: "+textsafe.Line(r.Error, 200), "")
		}
	case <-time.After(resultTimeout):
		t.finish(TransferFailed, "no confirmation from the recipient", "")
	case <-ctx.Done():
	}
}

func (n *Node) emitProgress(t *transferState, force bool) {
	t.mu.Lock()
	if !force && time.Since(t.lastEmit) < 200*time.Millisecond {
		t.mu.Unlock()
		return
	}
	t.lastEmit = time.Now()
	t.info.UpdatedAt = t.lastEmit
	info := t.info
	t.mu.Unlock()
	n.emit(Event{Kind: EventTransfer, PeerID: info.PeerID, Transfer: &info})
}

func (n *Node) handleFileOffer(s *transport.Session, o *protocol.FileOffer) {
	pid := s.PeerID()
	reject := func(reason string) {
		_ = s.Send(protocol.TypeFileReject, protocol.FileControl{TransferID: o.TransferID, Reason: reason})
	}
	if n.transferByID(o.TransferID) != nil {
		reject("duplicate transfer id")
		return
	}
	if o.Size > n.cfg.MaxFileSize() {
		reject(fmt.Sprintf("file is larger than the recipient's limit of %s", HumanSize(n.cfg.MaxFileSize())))
		return
	}
	if n.activeTransfers(false, "") >= maxIncomingActive || n.activeTransfers(false, pid) >= maxIncomingPerPeer {
		reject("recipient has too many active transfers")
		return
	}
	safe, err := transfer.SafeFileName(o.Name)
	if err != nil {
		reject("file name is not acceptable")
		return
	}
	t := &transferState{node: n, session: s, done: make(chan struct{}), info: TransferInfo{
		ID: o.TransferID, PeerID: pid, PeerName: n.peerName(pid), Name: safe, Size: o.Size,
		State: TransferIncoming, StartedAt: time.Now(), UpdatedAt: time.Now(),
	}}
	n.addTransfer(t)
	_ = n.store.SaveTransfer(context.Background(), storage.TransferRecord{ID: o.TransferID, PeerID: pid, Direction: "in", FileName: safe, Size: o.Size, State: TransferIncoming})
	info := t.snapshot()
	n.emit(Event{Kind: EventFileOffer, PeerID: pid, PeerName: info.PeerName, Transfer: &info})
	// Auto-expire unanswered offers.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		select {
		case <-time.After(offerTimeout):
			if t.snapshot().State == TransferIncoming {
				if t.finish(TransferRejected, "not answered in time", "") {
					reject("not answered in time")
				}
			}
		case <-t.done:
		case <-n.ctx.Done():
		}
	}()
}

// RespondFile accepts or declines an incoming file offer.
func (n *Node) RespondFile(_ context.Context, transferID string, accept bool) error {
	t := n.transferByID(transferID)
	if t == nil {
		return errors.New("unknown transfer")
	}
	t.mu.Lock()
	if t.info.State != TransferIncoming || t.info.Outgoing {
		t.mu.Unlock()
		return errors.New("this transfer is not waiting for an answer")
	}
	s := t.session
	t.mu.Unlock()
	if !s.Alive() {
		t.finish(TransferFailed, "connection lost", "")
		return ErrNotConnected
	}
	if !accept {
		t.finish(TransferRejected, "you declined it", "")
		return s.Send(protocol.TypeFileReject, protocol.FileControl{TransferID: transferID, Reason: "declined"})
	}
	in, err := transfer.CreateIncoming(n.cfg.DownloadDir(n.dirs), t.info.Name, t.info.Size)
	if err != nil {
		t.finish(TransferFailed, err.Error(), "")
		_ = s.Send(protocol.TypeFileReject, protocol.FileControl{TransferID: transferID, Reason: "recipient cannot store the file"})
		return err
	}
	t.mu.Lock()
	if t.info.State != TransferIncoming {
		// Cancelled while the file was being created.
		t.mu.Unlock()
		in.Abort()
		return errors.New("transfer was cancelled")
	}
	t.incoming = in
	t.info.State = TransferTransferring
	t.info.UpdatedAt = time.Now()
	t.mu.Unlock()
	if err := s.Send(protocol.TypeFileAccept, protocol.FileControl{TransferID: transferID}); err != nil {
		t.finish(TransferFailed, err.Error(), "")
		return err
	}
	n.emitProgress(t, true)
	return nil
}

// CancelTransfer cancels an active transfer in either direction.
func (n *Node) CancelTransfer(transferID string) error {
	t := n.transferByID(transferID)
	if t == nil {
		return errors.New("unknown transfer")
	}
	if t.snapshot().Done() {
		return errors.New("transfer already finished")
	}
	t.abort("cancelled by " + map[bool]string{true: "sender", false: "recipient"}[t.snapshot().Outgoing])
	return nil
}

func (n *Node) handleFileControl(s *transport.Session, typ string, c *protocol.FileControl) {
	t := n.transferByID(c.TransferID)
	if t == nil || t.snapshot().PeerID != s.PeerID() {
		return
	}
	reason := textsafe.Line(c.Reason, 200)
	switch typ {
	case protocol.TypeFileAccept:
		if t.snapshot().Outgoing && t.snapshot().State == TransferOffered {
			select {
			case t.accept <- true:
			default:
			}
		}
	case protocol.TypeFileReject:
		if t.snapshot().Outgoing {
			t.finish(TransferRejected, reason, "")
			select {
			case t.accept <- false:
			default:
			}
		}
	case protocol.TypeFileCancel:
		t.finish(TransferCancelled, "the peer cancelled: "+reason, "")
	}
}

func (n *Node) handleChunk(s *transport.Session, c *protocol.Chunk) error {
	t := n.transferByID(c.TransferID)
	if t == nil {
		return nil // late chunk after cancel: ignore
	}
	t.mu.Lock()
	if t.info.Outgoing || t.info.PeerID != s.PeerID() || t.info.State != TransferTransferring || t.incoming == nil {
		t.mu.Unlock()
		return nil
	}
	err := t.incoming.Write(c.Offset, c.Data)
	if err == nil {
		t.info.Transferred = t.incoming.Received()
	}
	t.mu.Unlock()
	if err != nil {
		t.abort("receive error: " + err.Error())
		return nil
	}
	n.emitProgress(t, false)
	return nil
}

func (n *Node) handleFileDone(s *transport.Session, d *protocol.FileDone) {
	t := n.transferByID(d.TransferID)
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.info.Outgoing || t.info.PeerID != s.PeerID() || t.info.State != TransferTransferring || t.incoming == nil {
		t.mu.Unlock()
		return
	}
	in := t.incoming
	t.incoming = nil
	t.mu.Unlock()
	path, err := in.Finish(d.Size, d.SHA256)
	if err != nil {
		t.finish(TransferFailed, err.Error(), "")
		_ = s.Send(protocol.TypeFileResult, protocol.FileResult{TransferID: d.TransferID, OK: false, Error: err.Error()})
		return
	}
	t.mu.Lock()
	t.info.Transferred = d.Size
	t.mu.Unlock()
	t.finish(TransferCompleted, "", path)
	_ = s.Send(protocol.TypeFileResult, protocol.FileResult{TransferID: d.TransferID, OK: true})
}

func (n *Node) handleFileResult(s *transport.Session, r *protocol.FileResult) {
	t := n.transferByID(r.TransferID)
	if t == nil || !t.snapshot().Outgoing || t.snapshot().PeerID != s.PeerID() {
		return
	}
	select {
	case t.result <- *r:
	default:
	}
}

// failTransfersForSession fails unfinished transfers bound to a session
// (used when a session is replaced by a newer one).
func (n *Node) failTransfersForSession(s *transport.Session, reason string) {
	n.mu.Lock()
	var list []*transferState
	for _, t := range n.transfers {
		list = append(list, t)
	}
	n.mu.Unlock()
	for _, t := range list {
		t.mu.Lock()
		match := t.session == s
		t.mu.Unlock()
		if match && !t.snapshot().Done() {
			t.finish(TransferFailed, reason, "")
		}
	}
}

// failStalledTransfers fails transfers that stopped making progress.
func (n *Node) failStalledTransfers(now time.Time) {
	n.mu.Lock()
	var list []*transferState
	for _, t := range n.transfers {
		list = append(list, t)
	}
	n.mu.Unlock()
	for _, t := range list {
		info := t.snapshot()
		if info.State == TransferTransferring && now.Sub(info.UpdatedAt) > stallTimeout {
			t.abort("no data received for two minutes")
		}
	}
}

func (n *Node) failTransfersFor(peer identity.PeerID, reason string) {
	n.mu.Lock()
	var list []*transferState
	for _, t := range n.transfers {
		if t.info.PeerID == peer {
			list = append(list, t)
		}
	}
	n.mu.Unlock()
	for _, t := range list {
		if !t.snapshot().Done() {
			t.finish(TransferFailed, reason, "")
		}
	}
}
