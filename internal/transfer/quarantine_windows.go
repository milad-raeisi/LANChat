//go:build windows

package transfer

import "os"

// markQuarantine adds the Mark-of-the-Web (Zone.Identifier stream, Internet
// zone) so SmartScreen and Office treat the received file as untrusted.
// Best effort: non-NTFS volumes do not support alternate data streams.
func markQuarantine(path string) {
	_ = os.WriteFile(path+":Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n"), 0o600)
}
