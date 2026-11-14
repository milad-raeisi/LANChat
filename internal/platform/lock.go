package platform

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ErrLocked is returned when another process holds the instance lock.
var ErrLocked = errors.New("another LANChat instance is already running with this profile")

// InstanceLock is an advisory, process-scoped exclusive lock on a file. The
// operating system releases it automatically if the process exits or
// crashes, so stale locks cannot block future launches.
type InstanceLock struct {
	f *os.File
}

// AcquireLock takes the exclusive instance lock at path without blocking.
func AcquireLock(path string) (*InstanceLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return &InstanceLock{f: f}, nil
}

// IsLocked reports whether another process currently holds the lock.
func IsLocked(path string) bool {
	l, err := AcquireLock(path)
	if err != nil {
		return errors.Is(err, ErrLocked)
	}
	_ = l.Release()
	return false
}

// HolderPID returns the PID recorded by the current lock holder, if any.
func HolderPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// Release unlocks and closes the lock file.
func (l *InstanceLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = unlockFile(l.f)
	err := l.f.Close()
	l.f = nil
	return err
}
