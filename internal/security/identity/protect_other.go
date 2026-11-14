//go:build !windows

package identity

import "errors"

// protect is a no-op on Unix-like systems: the key file is protected by
// 0600 permissions inside a 0700 directory. See docs/security for the
// rationale and future keychain integration notes.
func protect(plain []byte) ([]byte, string, error) {
	out := make([]byte, len(plain))
	copy(out, plain)
	return out, pemTypePlain, nil
}

func unprotect(blockType string, data []byte) ([]byte, error) {
	switch blockType {
	case pemTypePlain:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case pemTypeProtectd:
		return nil, errors.New("this key was sealed with Windows DPAPI and can only be opened by the Windows account that created it")
	default:
		return nil, errors.New("unsupported identity key type " + blockType)
	}
}
