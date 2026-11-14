package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// EnsurePrivateDir creates dir (and parents) and restricts it to the owner on
// Unix-like systems. On Windows, per-user profile directories are already
// protected by the user's ACLs.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(dir)
		if err != nil {
			return err
		}
		// Tighten permissions only for directories we own and that are too
		// permissive; never touch system directories.
		if st.Mode().Perm()&0o077 != 0 && isOwnedByCurrentUser(st) {
			if err := os.Chmod(dir, 0o700); err != nil {
				return fmt.Errorf("restrict permissions on %s: %w", dir, err)
			}
		}
	}
	return nil
}

// WriteFileAtomic writes data to a temporary file in the same directory and
// renames it over path, so readers never observe a partially written file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// CheckPrivateFile reports whether a sensitive file is readable by users other
// than the owner. It always returns nil on Windows where POSIX modes do not
// apply.
func CheckPrivateFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has permissions %v; expected 0600 (run: chmod 600 %q)", path, st.Mode().Perm(), path)
	}
	return nil
}
