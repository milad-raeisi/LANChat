// Package platform contains operating-system integration: per-user
// directories, single-instance locking and secure file helpers.
package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// HomeEnv is the environment variable that relocates every LANChat directory
// below a single root. It is primarily useful for running several independent
// profiles on one machine and for tests.
const HomeEnv = "LANCHAT_HOME"

// Dirs holds the per-user directories used by LANChat.
type Dirs struct {
	// Config holds config.toml.
	Config string
	// Data holds the identity key, the SQLite database and the lock file.
	Data string
	// Log holds rotated log files.
	Log string
}

// ResolveDirs returns the directories for the current platform. When home is
// non-empty (from --home or LANCHAT_HOME) every directory is placed beneath it.
func ResolveDirs(home string) (Dirs, error) {
	if home == "" {
		home = os.Getenv(HomeEnv)
	}
	if home != "" {
		abs, err := filepath.Abs(home)
		if err != nil {
			return Dirs{}, err
		}
		return Dirs{
			Config: abs,
			Data:   filepath.Join(abs, "data"),
			Log:    filepath.Join(abs, "logs"),
		}, nil
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return Dirs{}, errors.New("cannot determine the user home directory; set " + HomeEnv)
	}
	return resolveFor(runtime.GOOS, os.Getenv, userHome), nil
}

// resolveFor computes directories for a given OS. It is split out so that it
// can be tested for every platform from any platform.
func resolveFor(goos string, getenv func(string) string, home string) Dirs {
	join := filepath.Join
	switch goos {
	case "darwin":
		base := join(home, "Library", "Application Support", "LANChat")
		return Dirs{
			Config: base,
			Data:   base,
			Log:    join(home, "Library", "Logs", "LANChat"),
		}
	case "windows":
		roaming := getenv("APPDATA")
		if roaming == "" {
			roaming = join(home, "AppData", "Roaming")
		}
		local := getenv("LOCALAPPDATA")
		if local == "" {
			local = join(home, "AppData", "Local")
		}
		return Dirs{
			Config: join(roaming, "LANChat"),
			Data:   join(local, "LANChat"),
			Log:    join(local, "LANChat", "logs"),
		}
	default: // linux, *bsd and other unix: XDG Base Directory specification
		xdg := func(env, fallback string) string {
			if v := getenv(env); v != "" && filepath.IsAbs(v) {
				return v
			}
			return join(home, fallback)
		}
		return Dirs{
			Config: join(xdg("XDG_CONFIG_HOME", ".config"), "lanchat"),
			Data:   join(xdg("XDG_DATA_HOME", join(".local", "share")), "lanchat"),
			Log:    join(xdg("XDG_STATE_HOME", join(".local", "state")), "lanchat"),
		}
	}
}

// Ensure creates every directory with owner-only permissions.
func (d Dirs) Ensure() error {
	for _, p := range []string{d.Config, d.Data, d.Log} {
		if err := EnsurePrivateDir(p); err != nil {
			return err
		}
	}
	return nil
}

// ConfigFile returns the path of the TOML configuration file.
func (d Dirs) ConfigFile() string { return filepath.Join(d.Config, "config.toml") }

// IdentityFile returns the path of the private identity key.
func (d Dirs) IdentityFile() string { return filepath.Join(d.Data, "identity.key") }

// LockFile returns the path of the single-instance lock file.
func (d Dirs) LockFile() string { return filepath.Join(d.Data, "lanchat.lock") }

// DefaultDatabase returns the default SQLite database path.
func (d Dirs) DefaultDatabase() string { return filepath.Join(d.Data, "lanchat.db") }

// DefaultDownloads returns the default directory for received files.
func DefaultDownloads(d Dirs) string {
	if os.Getenv(HomeEnv) == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dl := filepath.Join(home, "Downloads")
			if st, err := os.Stat(dl); err == nil && st.IsDir() {
				return filepath.Join(dl, "LANChat")
			}
		}
	}
	return filepath.Join(d.Data, "downloads")
}
