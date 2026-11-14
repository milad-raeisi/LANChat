package discoverysrv

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// maxAuthorizedPeersFileBytes bounds the size of the authorized peers file.
const maxAuthorizedPeersFileBytes = 8 << 20

// defaultAuthReloadInterval is the minimum time between checks of the
// authorized peers file for changes.
const defaultAuthReloadInterval = 3 * time.Second

type peerSet map[identity.PeerID]struct{}

// authorizer decides which peer IDs may use the server. With an
// authorized peers file it re-reads the file when its modification time or
// size changes, checking at most once per minInterval.
type authorizer struct {
	allowAny    bool
	path        string
	log         *slog.Logger
	minInterval time.Duration

	set atomic.Pointer[peerSet]

	mu        sync.Mutex // guards the fields below and serializes reloads
	lastCheck time.Time
	modTime   time.Time
	size      int64
	missing   bool
}

func newAuthorizer(path string, allowAny bool, log *slog.Logger) (*authorizer, error) {
	a := &authorizer{allowAny: allowAny, path: path, log: log, minInterval: defaultAuthReloadInterval}
	empty := peerSet{}
	a.set.Store(&empty)
	if allowAny {
		return a, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("authorized peers file: %w", err)
	}
	set, err := readAuthorizedPeers(path)
	if err != nil {
		return nil, err
	}
	a.set.Store(&set)
	a.modTime, a.size = st.ModTime(), st.Size()
	return a, nil
}

// count returns the number of authorized peer IDs (0 with allowAny).
func (a *authorizer) count() int { return len(*a.set.Load()) }

// allowed reports whether id is currently authorized. Callers should call
// maybeReload first; allowed itself never touches the filesystem.
func (a *authorizer) allowed(id identity.PeerID) bool {
	if a.allowAny {
		return true
	}
	_, ok := (*a.set.Load())[id]
	return ok
}

// maybeReload re-reads the authorized peers file if it changed. A missing
// file revokes every authorization (fail closed); a file that cannot be
// parsed keeps the previous list.
func (a *authorizer) maybeReload(now time.Time) {
	if a.allowAny {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastCheck) < a.minInterval && !a.lastCheck.IsZero() {
		return
	}
	a.lastCheck = now
	st, err := os.Stat(a.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !a.missing {
				a.log.Warn("authorized peers file was removed; refusing every peer until it is restored", "path", a.path)
				empty := peerSet{}
				a.set.Store(&empty)
				a.missing = true
				a.modTime, a.size = time.Time{}, -1
			}
			return
		}
		a.log.Warn("cannot check authorized peers file; keeping the current list", "path", a.path, "err", err)
		return
	}
	if !a.missing && st.ModTime().Equal(a.modTime) && st.Size() == a.size {
		return
	}
	set, err := readAuthorizedPeers(a.path)
	if err != nil {
		a.log.Warn("authorized peers file is invalid; keeping the current list", "path", a.path, "err", err)
		// Remember this version so the error is reported once per change.
		// After a removal the list stays empty (fail closed).
		a.modTime, a.size, a.missing = st.ModTime(), st.Size(), false
		return
	}
	a.set.Store(&set)
	a.modTime, a.size, a.missing = st.ModTime(), st.Size(), false
	a.log.Info("authorized peers reloaded", "path", a.path, "count", len(set))
}

func readAuthorizedPeers(path string) (peerSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("authorized peers file: %w", err)
	}
	defer f.Close()
	set, err := parseAuthorizedPeers(io.LimitReader(f, maxAuthorizedPeersFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("authorized peers file %s: %w", path, err)
	}
	return set, nil
}

// parseAuthorizedPeers parses one peer ID per line. Everything after '#'
// is a comment; blank lines are ignored. Peer IDs are case-insensitive.
func parseAuthorizedPeers(r io.Reader) (peerSet, error) {
	set := peerSet{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	line, total := 0, 0
	for sc.Scan() {
		line++
		total += len(sc.Bytes()) + 1
		if total > maxAuthorizedPeersFileBytes {
			return nil, fmt.Errorf("file is larger than %d bytes", maxAuthorizedPeersFileBytes)
		}
		s := sc.Text()
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		id, err := identity.ParsePeerID(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q is not a LANChat peer ID (expected %d characters a-z and 2-7, as shown by `lanchat identity show`)", line, truncate(s, 40), identity.PeerIDLen)
		}
		set[id] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return set, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
