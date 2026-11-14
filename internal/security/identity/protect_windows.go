//go:build windows

package identity

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect encrypts the key with the Windows Data Protection API, scoped to
// the current user account.
func protect(plain []byte) ([]byte, string, error) {
	if len(plain) == 0 {
		return nil, "", errors.New("empty key")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var out windows.DataBlob
	desc, _ := windows.UTF16PtrFromString("LANChat identity key")
	if err := windows.CryptProtectData(&in, desc, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	sealed := make([]byte, out.Size)
	copy(sealed, unsafe.Slice(out.Data, out.Size))
	return sealed, pemTypeProtectd, nil
}

func unprotect(blockType string, data []byte) ([]byte, error) {
	switch blockType {
	case pemTypePlain:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case pemTypeProtectd:
		if len(data) == 0 {
			return nil, errors.New("empty protected key")
		}
		in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
		var out windows.DataBlob
		if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
			return nil, err
		}
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
		plain := make([]byte, out.Size)
		copy(plain, unsafe.Slice(out.Data, out.Size))
		return plain, nil
	default:
		return nil, errors.New("unsupported identity key type " + blockType)
	}
}
