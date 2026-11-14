package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/doctor"
	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

func (e *env) cmdConfig(args []string) int {
	if len(args) == 0 {
		e.errorf("usage: lanchat config show|edit|validate|path")
		return ExitUsage
	}
	path := e.dirs.ConfigFile()
	switch args[0] {
	case "path":
		e.printf("%s\n", path)
		return ExitOK
	case "show":
		cfg, err := e.loadConfig()
		if errors.Is(err, config.ErrNotFound) {
			e.errorf("no configuration yet at %s – run `lanchat` to set up", path)
			return ExitConfig
		}
		var ve *config.ValidationError
		if err != nil && !errors.As(err, &ve) {
			e.errorf("%v", err)
			return ExitConfig
		}
		out, _ := config.Encode(cfg)
		e.printf("# %s\n%s", path, out)
		if err != nil {
			e.errorf("%v", err)
			return ExitConfig
		}
		return ExitOK
	case "validate":
		_, err := e.loadConfig()
		if errors.Is(err, config.ErrNotFound) {
			e.errorf("no configuration at %s – run `lanchat` to set up", path)
			return ExitConfig
		}
		if err != nil {
			e.errorf("%v", err)
			return ExitConfig
		}
		e.printf("Configuration is valid: %s\n", path)
		return ExitOK
	case "edit":
		if _, err := os.Stat(path); err != nil {
			if err := e.dirs.Ensure(); err != nil {
				e.errorf("%v", err)
				return ExitError
			}
			if err := config.Save(path, config.Default()); err != nil {
				e.errorf("%v", err)
				return ExitError
			}
		}
		editor := os.Getenv("VISUAL")
		if editor == "" {
			editor = os.Getenv("EDITOR")
		}
		if editor == "" {
			if runtime.GOOS == "windows" {
				editor = "notepad"
			} else if _, err := exec.LookPath("nano"); err == nil {
				editor = "nano"
			} else {
				editor = "vi"
			}
		}
		parts := strings.Fields(editor)
		cmd := exec.Command(parts[0], append(parts[1:], path)...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			e.errorf("editor %q failed: %v", editor, err)
			return ExitError
		}
		if _, err := e.loadConfig(); err != nil {
			e.errorf("%v", err)
			e.errorf("the file was saved but is not valid; run `lanchat config edit` again")
			return ExitConfig
		}
		e.printf("Configuration saved and valid. Restart LANChat to apply network changes.\n")
		return ExitOK
	}
	e.errorf("unknown config command %q", args[0])
	return ExitUsage
}

func (e *env) cmdNetwork(args []string) int {
	if len(args) == 0 {
		e.errorf("usage: lanchat network status|interfaces|diagnose")
		return ExitUsage
	}
	switch args[0] {
	case "interfaces":
		list, err := netif.List()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		rec := netif.Recommend(list)
		tw := tabwriter.NewWriter(e.stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "INTERFACE\tSTATE\tADDRESSES\tNOTES")
		for _, it := range list {
			state := "down"
			if it.Up {
				state = "up"
			}
			if it.Multicast {
				state += ",multicast"
			}
			var addrs []string
			for _, a := range it.Addrs {
				addrs = append(addrs, a.String())
			}
			note := it.Note
			if rec != nil && rec.Name == it.Name {
				note = "recommended"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", it.Name, state, strings.Join(addrs, " "), note)
		}
		_ = tw.Flush()
		e.printf("\nSet a specific interface with `network.interface` in the configuration (default \"auto\").\n")
		return ExitOK
	case "status":
		cfg, err := e.loadConfig()
		if err != nil {
			e.errorf("%v", err)
			return ExitConfig
		}
		network, addr := node.ListenAddress(cfg.Network)
		e.printf("Mode:          %s\n", cfg.Network.Mode)
		e.printf("Interface:     %s\n", cfg.Network.Interface)
		e.printf("Listen:        %s (%s)\n", addr, network)
		e.printf("Discovery:     mDNS=%v static peers=%d managed=%q\n", cfg.Discovery.MDNSEnabled, len(cfg.Discovery.StaticPeers), cfg.Discovery.ManagedServer)
		if platform.IsLocked(e.dirs.LockFile()) {
			e.printf("LANChat:       running (PID %d)\n", platform.HolderPID(e.dirs.LockFile()))
		} else {
			e.printf("LANChat:       not running\n")
		}
		if list, err := netif.List(); err == nil {
			if sel, err := netif.Select(list, cfg.Network.Interface); err == nil {
				for _, it := range sel {
					var addrs []string
					for _, a := range it.Addrs {
						addrs = append(addrs, a.IP.String())
					}
					e.printf("Using:         %s %s\n", it.Name, strings.Join(addrs, " "))
				}
			} else {
				e.printf("Using:         none – %v\n", err)
			}
		}
		return ExitOK
	case "diagnose":
		return e.cmdDoctor(args[1:], true)
	}
	e.errorf("unknown network command %q", args[0])
	return ExitUsage
}

func (e *env) cmdDoctor(args []string, networkOnly bool) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	verbose := fs.Bool("verbose", false, "show details")
	fs.BoolVar(verbose, "v", false, "show details")
	browse := fs.Duration("timeout", 4*time.Second, "how long to listen for peers")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	failures := doctor.Run(context.Background(), doctor.Options{Dirs: e.dirs, Verbose: *verbose, Browse: *browse, NetworkOnly: networkOnly}, e.stdout)
	if failures > 0 {
		return ExitError
	}
	return ExitOK
}

func (e *env) openStore() (*storage.Store, config.Config, error) {
	cfg, err := e.loadConfig()
	if err != nil {
		return nil, cfg, err
	}
	st, err := storage.Open(context.Background(), cfg.DatabasePath(e.dirs))
	return st, cfg, err
}

func (e *env) refuseIfRunning(action string) bool {
	if platform.IsLocked(e.dirs.LockFile()) {
		e.errorf("LANChat is running (PID %d). Quit it before you %s.", platform.HolderPID(e.dirs.LockFile()), action)
		return true
	}
	return false
}

func (e *env) cmdPeers(args []string) int {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		st, _, err := e.openStore()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		defer st.Close()
		peers, err := st.ListPeers(context.Background())
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		if len(peers) == 0 {
			e.printf("No peers yet. Peers appear after they connect for the first time.\n")
			return ExitOK
		}
		tw := tabwriter.NewWriter(e.stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tDEVICE\tTRUST\tVERIFIED\tLAST SEEN\tPEER ID")
		for _, p := range peers {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\n", textsafe.Line(p.DisplayName, 32), textsafe.Line(p.DeviceName, 32),
				p.Trust, p.Verified, p.LastSeen.Local().Format("2006-01-02 15:04"), p.ID)
		}
		_ = tw.Flush()
		return ExitOK
	case "revoke":
		if len(args) < 2 {
			e.errorf("usage: lanchat peers revoke <peer-id or unique name>")
			return ExitUsage
		}
		if e.refuseIfRunning("revoke trust (or use /unpair inside LANChat)") {
			return ExitRunning
		}
		st, _, err := e.openStore()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		defer st.Close()
		peers, _ := st.ListPeers(context.Background())
		var match []storage.Peer
		for _, p := range peers {
			if string(p.ID) == args[1] || (len(args[1]) >= 6 && strings.HasPrefix(string(p.ID), strings.ToLower(args[1]))) || strings.EqualFold(p.DisplayName, args[1]) {
				match = append(match, p)
			}
		}
		if len(match) != 1 {
			e.errorf("%q matches %d peers; use the full peer ID from `lanchat peers list`", args[1], len(match))
			return ExitUsage
		}
		p := match[0]
		if err := st.SetTrust(context.Background(), p.ID, storage.TrustRevoked, false, time.Now()); err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		if _, err := st.FailPendingFor(context.Background(), p.ID, "peer trust revoked"); err != nil {
			e.errorf("%v", err)
		}
		e.printf("Trust in %s (%s) revoked.\n", textsafe.Line(p.DisplayName, 32), p.ID)
		return ExitOK
	}
	e.errorf("unknown peers command %q", args[0])
	return ExitUsage
}

func (e *env) cmdIdentity(args []string) int {
	if len(args) == 0 {
		args = []string{"show"}
	}
	path := e.dirs.IdentityFile()
	switch args[0] {
	case "show", "fingerprint":
		id, err := identity.Load(path)
		if errors.Is(err, identity.ErrNoIdentity) {
			e.errorf("no identity yet – run `lanchat` to create one")
			return ExitError
		}
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		if args[0] == "fingerprint" {
			e.printf("%s\n", identity.FormatFingerprint(id.Fingerprint()))
			return ExitOK
		}
		e.printf("Peer ID:      %s\n", id.ID())
		e.printf("Short ID:     %s\n", id.ID().Short())
		e.printf("Fingerprint:  %s\n", identity.FormatFingerprint(id.Fingerprint()))
		e.printf("Key type:     Ed25519\n")
		e.printf("Key file:     %s\n", path)
		if cfg, err := e.loadConfig(); err == nil {
			e.printf("Display name: %s\n", cfg.User.DisplayName)
		}
		if err := platform.CheckPrivateFile(path); err != nil {
			e.errorf("warning: %v", err)
		}
		return ExitOK
	case "reset":
		fs := flag.NewFlagSet("reset", flag.ContinueOnError)
		fs.SetOutput(e.stderr)
		yes := fs.Bool("yes", false, "do not ask for confirmation")
		if err := fs.Parse(args[1:]); err != nil {
			return ExitUsage
		}
		if e.refuseIfRunning("reset your identity") {
			return ExitRunning
		}
		old, err := identity.Load(path)
		if err != nil && !errors.Is(err, identity.ErrNoIdentity) {
			e.errorf("current identity cannot be read (%v); it will be replaced", err)
		}
		e.printf("Resetting your identity:\n")
		e.printf("  • A new key, peer ID and fingerprint are generated; the old private key is deleted.\n")
		e.printf("  • Everyone who paired with you will see a NEW, unpaired identity and must verify and pair again.\n")
		e.printf("  • Their LANChat will warn that a new key uses your name – tell them in person.\n")
		e.printf("  • Your message history and the peers you trust stay as they are.\n")
		if old != nil {
			e.printf("  Current peer ID: %s\n", old.ID())
		}
		if !*yes && !e.confirm("This cannot be undone.", "reset") {
			e.printf("Cancelled. Your identity was not changed.\n")
			return ExitOK
		}
		if err := e.dirs.Ensure(); err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		id, err := identity.Generate()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		if err := id.Save(path); err != nil {
			e.errorf("save new identity: %v", err)
			return ExitError
		}
		e.printf("New identity created.\nPeer ID:     %s\nFingerprint: %s\n", id.ID(), identity.FormatFingerprint(id.Fingerprint()))
		return ExitOK
	}
	e.errorf("unknown identity command %q", args[0])
	return ExitUsage
}

func (e *env) cmdData(args []string) int {
	if len(args) == 0 {
		e.errorf("usage: lanchat data backup <file> | export <file> [--format json|text] [--conversation ID] | purge")
		return ExitUsage
	}
	switch args[0] {
	case "backup":
		if len(args) < 2 {
			e.errorf("usage: lanchat data backup <file>")
			return ExitUsage
		}
		st, _, err := e.openStore()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		defer st.Close()
		if err := st.Backup(context.Background(), args[1]); err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		e.printf("Database backed up to %s\n", args[1])
		return ExitOK
	case "export":
		fs := flag.NewFlagSet("export", flag.ContinueOnError)
		fs.SetOutput(e.stderr)
		format := fs.String("format", "json", "json or text")
		conv := fs.String("conversation", "", "conversation ID (default: all)")
		var file string
		rest := args[1:]
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			file, rest = rest[0], rest[1:]
		}
		if err := fs.Parse(rest); err != nil {
			return ExitUsage
		}
		if file == "" && fs.NArg() > 0 {
			file = fs.Arg(0)
		}
		if file == "" || (*format != "json" && *format != "text") {
			e.errorf("usage: lanchat data export <file> [--format json|text] [--conversation ID]")
			return ExitUsage
		}
		st, _, err := e.openStore()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		defer st.Close()
		n, err := node.ExportConversation(context.Background(), st, *conv, file, *format)
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		e.printf("Exported %d message(s) to %s\n", n, file)
		return ExitOK
	case "purge":
		fs := flag.NewFlagSet("purge", flag.ContinueOnError)
		fs.SetOutput(e.stderr)
		yes := fs.Bool("yes", false, "do not ask for confirmation")
		if err := fs.Parse(args[1:]); err != nil {
			return ExitUsage
		}
		if e.refuseIfRunning("delete history") {
			return ExitRunning
		}
		if !*yes && !e.confirm("This permanently deletes all locally stored messages (peers and trust are kept).", "delete") {
			e.printf("Cancelled.\n")
			return ExitOK
		}
		st, _, err := e.openStore()
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		defer st.Close()
		n, err := st.DeleteHistory(context.Background(), "")
		if err != nil {
			e.errorf("%v", err)
			return ExitError
		}
		e.printf("Deleted %d message(s).\n", n)
		return ExitOK
	}
	e.errorf("unknown data command %q", args[0])
	return ExitUsage
}
