//go:build windows

package platform

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Windows byte-range locks are mandatory: a locked range cannot be read by
// other handles. Lock a single byte far beyond the PID written at the start
// of the file, so other processes can still read who holds the lock.
const lockOffset = 0x7FFFFFFF

func lockOverlapped() *windows.Overlapped {
	return &windows.Overlapped{Offset: lockOffset}
}

func lockFile(f *os.File) error {
	ol := lockOverlapped()
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	ol := lockOverlapped()
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
