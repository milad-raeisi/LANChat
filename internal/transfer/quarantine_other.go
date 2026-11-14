//go:build !darwin && !windows

package transfer

// markQuarantine is a no-op: Linux has no system-wide quarantine marker.
// Received files are written without execute permission (0600).
func markQuarantine(string) {}
