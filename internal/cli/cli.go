// Package cli implements the `lanchat` command line: starting the
// interactive application and the administrative subcommands.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/charmbracelet/x/term"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/tui"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitError      = 1
	ExitUsage      = 2
	ExitConfig     = 3
	ExitRunning    = 4
	ExitNoTerminal = 5
)

// env bundles process I/O so commands are testable.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	dirs   platform.Dirs
	debug  bool
}

func (e *env) printf(format string, args ...any) { fmt.Fprintf(e.stdout, format, args...) }
func (e *env) errorf(format string, args ...any) {
	fmt.Fprintf(e.stderr, "lanchat: "+format+"\n", args...)
}

const usage = `LANChat – secure terminal messaging on your local network.

Usage:
  lanchat [flags]                 start LANChat (runs the setup wizard on first launch)
  lanchat <command> [arguments]

Flags:
  --setup            run the setup wizard again
  --home DIR         keep all LANChat files below DIR (also: LANCHAT_HOME)
  --debug            write debug-level logs
  --version          print version information
  --help             show this help

Commands:
  config show|edit|validate|path        inspect or change the configuration
  network status|interfaces|diagnose    network information and diagnostics
  peers list                            list known peers and their trust state
  peers revoke <peer>                   revoke trust in a peer
  identity show|fingerprint             show your identity
  identity reset                        replace your identity (requires confirmation)
  data backup <file>                    copy the message database
  data export <file> [--format json|text] [--conversation ID]
  data purge                            delete all stored message history
  doctor [--verbose]                    run diagnostics
  version                               print version information

Exit codes: 0 ok, 1 error, 2 usage, 3 invalid configuration,
            4 LANChat already running, 5 no interactive terminal.
`

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lanchat", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	setup := fs.Bool("setup", false, "")
	home := fs.String("home", "", "")
	debug := fs.Bool("debug", false, "")
	version := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "lanchat: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if *help {
		fmt.Fprint(stdout, usage)
		return ExitOK
	}
	if *version {
		fmt.Fprintln(stdout, buildinfo.Long())
		return ExitOK
	}
	dirs, err := platform.ResolveDirs(*home)
	if err != nil {
		fmt.Fprintf(stderr, "lanchat: %v\n", err)
		return ExitError
	}
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, dirs: dirs, debug: *debug}
	rest := fs.Args()
	if len(rest) == 0 {
		return e.runApp(*setup)
	}
	cmd, sub := rest[0], rest[1:]
	switch cmd {
	case "config":
		return e.cmdConfig(sub)
	case "network":
		return e.cmdNetwork(sub)
	case "peers":
		return e.cmdPeers(sub)
	case "identity":
		return e.cmdIdentity(sub)
	case "data":
		return e.cmdData(sub)
	case "doctor":
		return e.cmdDoctor(sub, false)
	case "version":
		e.printf("%s\n", buildinfo.Long())
		return ExitOK
	case "help":
		e.printf("%s", usage)
		return ExitOK
	}
	e.errorf("unknown command %q\n\n%s", cmd, usage)
	return ExitUsage
}

func isTerminal(r io.Reader, w io.Writer) bool {
	in, ok1 := r.(*os.File)
	out, ok2 := w.(*os.File)
	return ok1 && ok2 && term.IsTerminal(in.Fd()) && term.IsTerminal(out.Fd())
}

// loadConfig loads and validates the configuration.
func (e *env) loadConfig() (config.Config, error) {
	cfg, res, err := config.Load(e.dirs.ConfigFile())
	if err != nil {
		return cfg, err
	}
	for _, k := range res.UnknownKeys {
		e.errorf("warning: unknown configuration key %q is ignored", k)
	}
	return cfg, cfg.Validate()
}

func (e *env) runApp(forceSetup bool) int {
	if !isTerminal(e.stdin, e.stdout) {
		e.errorf("LANChat's chat interface needs an interactive terminal.\nUse `lanchat --help` for non-interactive commands.")
		return ExitNoTerminal
	}
	if err := e.dirs.Ensure(); err != nil {
		e.errorf("%v", err)
		return ExitError
	}
	if platform.IsLocked(e.dirs.LockFile()) {
		e.errorf("%v (PID %d). Each profile can run once; use --home for a second profile.", platform.ErrLocked, platform.HolderPID(e.dirs.LockFile()))
		return ExitRunning
	}

	cfg, err := e.loadConfig()
	var existing *config.Config
	if err == nil {
		existing = &cfg
	} else if !errors.Is(err, config.ErrNotFound) {
		var ve *config.ValidationError
		if !errors.As(err, &ve) {
			e.errorf("%v", err)
			e.errorf("fix the file with `lanchat config edit` or recreate it with `lanchat --setup`")
			return ExitConfig
		}
		if !forceSetup {
			e.errorf("%v", err)
			e.errorf("fix it with `lanchat config edit` or rerun the wizard with `lanchat --setup`")
			return ExitConfig
		}
		existing = &cfg
	}
	if forceSetup || existing == nil {
		saved, ok, err := tui.RunWizard(e.dirs, existing)
		if err != nil {
			e.errorf("setup failed: %v", err)
			return ExitError
		}
		if !ok {
			e.printf("Setup cancelled. Nothing was changed.\n")
			return ExitOK
		}
		cfg = saved
	}
	return e.startNode(cfg)
}

func (e *env) startNode(cfg config.Config) int {
	lock, err := platform.AcquireLock(e.dirs.LockFile())
	if err != nil {
		e.errorf("%v", err)
		if errors.Is(err, platform.ErrLocked) {
			return ExitRunning
		}
		return ExitError
	}
	defer lock.Release()

	level := cfg.Logging.Level
	if e.debug {
		level = "debug"
	}
	logFile := cfg.Logging.File
	if logFile == "" {
		logFile = e.dirs.Log + string(os.PathSeparator) + "lanchat.log"
	}
	logger, closer, err := logging.Setup(logging.Options{Level: level, File: logFile, MaxSizeMB: cfg.Logging.MaxSizeMB, MaxFiles: cfg.Logging.MaxFiles})
	if err != nil {
		e.errorf("cannot open log file (%v); continuing without logs", err)
		logger = logging.Discard()
	} else {
		defer closer.Close()
	}
	slog.SetDefault(logger)

	id, created, err := identity.LoadOrCreate(e.dirs.IdentityFile())
	if err != nil {
		e.errorf("identity: %v", err)
		return ExitError
	}
	if created {
		logger.Info("generated new identity", "peer_id", string(id.ID()))
	}
	if err := platform.CheckPrivateFile(e.dirs.IdentityFile()); err != nil {
		e.errorf("warning: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := storage.Open(ctx, cfg.DatabasePath(e.dirs))
	if err != nil {
		e.errorf("database: %v", err)
		if errors.Is(err, storage.ErrCorrupt) {
			e.errorf("Recovery: move %s aside (LANChat will create a new, empty database)\nor restore a copy made with `lanchat data backup`.", cfg.DatabasePath(e.dirs))
		}
		return ExitError
	}
	defer store.Close()

	n, err := node.New(node.Options{Config: cfg, Dirs: e.dirs, Identity: id, Store: store, Logger: logger})
	if err != nil {
		e.errorf("%v", err)
		return ExitConfig
	}
	if err := n.Start(ctx); err != nil {
		e.errorf("%v", err)
		return ExitError
	}
	save := func(c config.Config) error { return config.Save(e.dirs.ConfigFile(), c) }
	uiErr := tui.RunChat(n, save)
	_ = n.Close()
	if uiErr != nil && !errors.Is(uiErr, context.Canceled) {
		e.errorf("interface error: %v", uiErr)
		return ExitError
	}
	return ExitOK
}

// confirm asks a yes/no question; only an exact typed word counts as yes.
func (e *env) confirm(prompt, word string) bool {
	e.printf("%s\nType %q to continue: ", prompt, word)
	line, _ := bufio.NewReader(e.stdin).ReadString('\n')
	return strings.TrimSpace(line) == word
}
