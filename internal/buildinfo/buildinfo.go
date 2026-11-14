// Package buildinfo exposes version metadata injected at build time.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// These variables are overridden at link time by GoReleaser / the Makefile:
//
//	-ldflags "-X github.com/milad-raeisi/LANChat/internal/buildinfo.Version=v1.0.0"
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// ProtocolVersion is the LANChat wire protocol version. It is versioned
// independently from the application release version.
const ProtocolVersion = 1

// MinProtocolVersion is the oldest wire protocol version this build accepts.
const MinProtocolVersion = 1

// AppName is the human-readable product name.
const AppName = "LANChat"

// Short returns the version string for display in the UI.
func Short() string {
	v := Version
	if v == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
	}
	return v
}

// Long returns a multi-field version description for --version output.
func Long() string {
	commit := Commit
	if commit == "" {
		commit = vcsRevision()
	}
	if commit == "" {
		commit = "unknown"
	}
	date := Date
	if date == "" {
		date = "unknown"
	}
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s, %s, protocol v%d)",
		AppName, Short(), commit, date, runtime.GOOS, runtime.GOARCH, runtime.Version(), ProtocolVersion)
}

func vcsRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" && modified == "true" {
		rev += "-dirty"
	}
	return rev
}
