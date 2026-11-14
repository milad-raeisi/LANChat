package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveForPlatforms(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	home := "/home/u"

	d := resolveFor("linux", env(nil), home)
	if d.Config != filepath.Join(home, ".config", "lanchat") || d.Data != filepath.Join(home, ".local", "share", "lanchat") {
		t.Fatalf("linux defaults wrong: %+v", d)
	}
	// XDG values must be absolute paths; build one that is absolute on the
	// host running the test (resolveFor uses the host's path rules).
	xdgConfig := filepath.Join(t.TempDir(), "cfg")
	d = resolveFor("linux", env(map[string]string{"XDG_CONFIG_HOME": xdgConfig, "XDG_DATA_HOME": "relative/ignored"}), home)
	if d.Config != filepath.Join(xdgConfig, "lanchat") {
		t.Fatalf("XDG_CONFIG_HOME not honoured: %+v", d)
	}
	if d.Data != filepath.Join(home, ".local", "share", "lanchat") {
		t.Fatalf("relative XDG_DATA_HOME must be ignored per spec: %+v", d)
	}
	d = resolveFor("darwin", env(nil), home)
	if d.Config != filepath.Join(home, "Library", "Application Support", "LANChat") {
		t.Fatalf("darwin config wrong: %+v", d)
	}
	d = resolveFor("windows", env(map[string]string{"APPDATA": `C:\R`, "LOCALAPPDATA": `C:\L`}), home)
	if d.Config != filepath.Join(`C:\R`, "LANChat") || d.Data != filepath.Join(`C:\L`, "LANChat") {
		t.Fatalf("windows dirs wrong: %+v", d)
	}
}

func TestResolveDirsHomeOverride(t *testing.T) {
	root := t.TempDir()
	d, err := ResolveDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	if d.Config != root || d.Data != filepath.Join(root, "data") {
		t.Fatalf("unexpected dirs %+v", d)
	}
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFileAtomicAndPerms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "two" {
		t.Fatalf("got %q", b)
	}
	if err := CheckPrivateFile(p); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(p, 0o644)
		if err := CheckPrivateFile(p); err == nil {
			t.Fatal("expected permission warning for world-readable key")
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestInstanceLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	l, err := AcquireLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if _, err := AcquireLock(p); !errors.Is(err, ErrLocked) {
		// flock locks are per open file description, so a second open in the
		// same process must fail to acquire.
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	if !IsLocked(p) {
		t.Fatal("IsLocked should report true while held")
	}
	if HolderPID(p) != os.Getpid() {
		t.Fatalf("holder pid = %d", HolderPID(p))
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := AcquireLock(p)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	_ = l2.Release()
}
