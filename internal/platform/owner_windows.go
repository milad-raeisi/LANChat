//go:build windows

package platform

import "os"

func isOwnedByCurrentUser(os.FileInfo) bool { return false }
