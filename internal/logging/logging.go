// Package logging configures structured logging with log/slog. Logs are
// written to a size-rotated file and never to the terminal, so they cannot
// corrupt the TUI. Sensitive attribute keys are redacted defensively.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Options configures Setup.
type Options struct {
	Level     string
	File      string
	MaxSizeMB int
	MaxFiles  int
}

// ParseLevel converts a level name into a slog.Level, defaulting to info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// sensitiveKeys are attribute keys whose values must never reach a log file.
var sensitiveKeys = map[string]bool{
	"body": true, "message_body": true, "private_key": true, "privkey": true,
	"secret": true, "password": true, "token": true, "key_material": true,
}

// Redact replaces values of sensitive attribute keys.
func Redact(_ []string, a slog.Attr) slog.Attr {
	if sensitiveKeys[strings.ToLower(a.Key)] {
		return slog.String(a.Key, "[redacted]")
	}
	return a
}

// Setup creates a logger writing to a rotating file. The returned closer
// flushes and closes the file.
func Setup(opts Options) (*slog.Logger, io.Closer, error) {
	if opts.File == "" {
		return nil, nil, fmt.Errorf("log file path is required")
	}
	if opts.MaxSizeMB <= 0 {
		opts.MaxSizeMB = 5
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 3
	}
	if err := os.MkdirAll(filepath.Dir(opts.File), 0o700); err != nil {
		return nil, nil, err
	}
	w, err := NewRotatingWriter(opts.File, int64(opts.MaxSizeMB)*1024*1024, opts.MaxFiles)
	if err != nil {
		return nil, nil, err
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level:       ParseLevel(opts.Level),
		ReplaceAttr: Redact,
	})
	return slog.New(h), w, nil
}

// Discard returns a logger that drops everything (used in tests and when
// logging cannot be initialised).
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 100}))
}

// RotatingWriter is an io.WriteCloser that rotates its file when it exceeds
// maxBytes, keeping at most maxFiles old files (path.1 … path.N).
type RotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	f        *os.File
	size     int64
}

// NewRotatingWriter opens (or creates) path for appending.
func NewRotatingWriter(path string, maxBytes int64, maxFiles int) (*RotatingWriter, error) {
	w := &RotatingWriter{path: path, maxBytes: maxBytes, maxFiles: maxFiles}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Write implements io.Writer.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size+int64(len(p)) > w.maxBytes && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingWriter) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	w.f = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxFiles))
	for i := w.maxFiles - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

// Close closes the underlying file.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
