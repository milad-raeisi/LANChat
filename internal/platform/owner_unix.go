//go:build !windows

package platform

import (
	"os"
	"syscall"
)

func isOwnedByCurrentUser(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(sys.Uid) == os.Getuid()
}
