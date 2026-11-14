//go:build darwin

package transfer

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// markQuarantine tags a received file the way browsers do, so Gatekeeper
// warns before it is opened or executed. Best effort.
func markQuarantine(path string) {
	value := fmt.Sprintf("0081;%x;LANChat;", time.Now().Unix())
	_ = unix.Setxattr(path, "com.apple.quarantine", []byte(value), 0)
}
