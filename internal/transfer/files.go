// Package transfer contains the filesystem side of peer-to-peer file
// transfer: sanitising names chosen by remote peers, choosing collision-free
// destinations inside the download directory, and writing incoming data to
// a temporary file whose size and SHA-256 are verified before it becomes
// visible under its final name. Received files are never opened or executed.
package transfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

const maxNameBytes = 200

// ErrUnsafeName is returned when nothing usable remains of a remote name.
var ErrUnsafeName = errors.New("file name is not usable")

var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// SafeFileName converts a file name received from a peer into a single,
// portable path component. Directory components (with either separator),
// drive letters, control characters, characters invalid on Windows,
// leading dots and reserved device names are removed or neutralised. The
// result is never ".", ".." or empty and never contains a separator.
func SafeFileName(name string) (string, error) {
	name = textsafe.Line(name, 0)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '<', '>', ':', '"', '|', '?', '*', '/', '\\':
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	name = b.String()
	name = strings.TrimLeft(name, ". ")
	name = strings.TrimRight(name, ". ")
	if name == "" {
		return "", ErrUnsafeName
	}
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if windowsReserved[strings.ToLower(strings.TrimSpace(stem))] {
		name = "_" + name
	}
	if len(name) > maxNameBytes {
		ext := filepath.Ext(name)
		if len(ext) > 20 || !utf8.ValidString(ext) {
			ext = ""
		}
		keep := maxNameBytes - len(ext)
		for keep > 0 && !utf8.RuneStart(name[keep]) {
			keep--
		}
		name = strings.TrimRight(name[:keep], ". ") + ext
	}
	return name, nil
}

// UniquePath returns a path inside dir for name that does not currently
// exist, appending " (n)" before the extension when necessary.
func UniquePath(dir, name string) (string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; i < 10000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		p := filepath.Join(dir, candidate)
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			return p, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("no free file name for %q in %s", name, dir)
}

// IncomingFile receives a file into a temporary location.
type IncomingFile struct {
	dir      string
	name     string
	tmpPath  string
	f        *os.File
	expected int64
	received int64
	h        hash.Hash
}

// ErrOutOfOrder is returned when a chunk does not continue the file.
var ErrOutOfOrder = errors.New("chunk offset does not match received data")

// ErrTooMuchData is returned when the peer sends more than it announced.
var ErrTooMuchData = errors.New("peer sent more data than announced")

// CreateIncoming prepares to receive expectedSize bytes for a file that will
// be named safeName (already sanitised) inside dir.
func CreateIncoming(dir, safeName string, expectedSize int64) (*IncomingFile, error) {
	if safeName == "" || strings.ContainsAny(safeName, `/\`) || safeName == "." || safeName == ".." {
		return nil, ErrUnsafeName
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create download directory: %w", err)
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%s.lanchat-part", truncateName(safeName, 80), hex.EncodeToString(rnd[:])))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create temporary file: %w", err)
	}
	return &IncomingFile{dir: dir, name: safeName, tmpPath: tmp, f: f, expected: expectedSize, h: sha256.New()}, nil
}

func truncateName(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Write appends a chunk. Chunks must arrive in order without gaps.
func (f *IncomingFile) Write(offset uint64, data []byte) error {
	if f.f == nil {
		return os.ErrClosed
	}
	if offset != uint64(f.received) {
		return ErrOutOfOrder
	}
	if f.received+int64(len(data)) > f.expected {
		return ErrTooMuchData
	}
	if _, err := f.f.Write(data); err != nil {
		return fmt.Errorf("write received data: %w", err)
	}
	f.h.Write(data)
	f.received += int64(len(data))
	return nil
}

// Received returns the number of bytes written so far.
func (f *IncomingFile) Received() int64 { return f.received }

// Expected returns the announced size.
func (f *IncomingFile) Expected() int64 { return f.expected }

// Finish verifies the size and SHA-256 and moves the file to a
// collision-free final path, which it returns. On any verification failure
// the temporary file is deleted.
func (f *IncomingFile) Finish(size int64, sha256Hex string) (string, error) {
	if f.f == nil {
		return "", os.ErrClosed
	}
	if err := f.f.Sync(); err != nil {
		f.Abort()
		return "", err
	}
	if err := f.f.Close(); err != nil {
		f.f = nil
		_ = os.Remove(f.tmpPath)
		return "", err
	}
	f.f = nil
	if size != f.expected || f.received != f.expected {
		_ = os.Remove(f.tmpPath)
		return "", fmt.Errorf("size mismatch: announced %d, final %d, received %d", f.expected, size, f.received)
	}
	got := hex.EncodeToString(f.h.Sum(nil))
	if !strings.EqualFold(got, sha256Hex) {
		_ = os.Remove(f.tmpPath)
		return "", fmt.Errorf("integrity check failed: SHA-256 mismatch")
	}
	final, err := UniquePath(f.dir, f.name)
	if err != nil {
		_ = os.Remove(f.tmpPath)
		return "", err
	}
	if err := os.Rename(f.tmpPath, final); err != nil {
		_ = os.Remove(f.tmpPath)
		return "", fmt.Errorf("move received file into place: %w", err)
	}
	markQuarantine(final)
	return final, nil
}

// SHA256 returns the hash of the data received so far.
func (f *IncomingFile) SHA256() string { return hex.EncodeToString(f.h.Sum(nil)) }

// Abort closes and deletes the temporary file.
func (f *IncomingFile) Abort() {
	if f.f != nil {
		_ = f.f.Close()
		f.f = nil
	}
	_ = os.Remove(f.tmpPath)
}

// OpenOutgoing opens a local file for sending. Only regular files are
// allowed; directories, devices, sockets and pipes are refused.
func OpenOutgoing(path string) (*os.File, string, int64, error) {
	if path == "" {
		return nil, "", 0, errors.New("no file given")
	}
	if strings.HasPrefix(path, "~"+string(filepath.Separator)) || path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), string(filepath.Separator)))
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", 0, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, "", 0, err
	}
	if !st.Mode().IsRegular() {
		return nil, "", 0, fmt.Errorf("%s is not a regular file", abs)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, "", 0, err
	}
	return f, filepath.Base(abs), st.Size(), nil
}

// CleanupStale removes leftover temporary files from interrupted transfers.
func CleanupStale(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), ".") && strings.HasSuffix(e.Name(), ".lanchat-part") {
			if os.Remove(filepath.Join(dir, e.Name())) == nil {
				n++
			}
		}
	}
	return n
}
