// Command lanchat-discovery is the optional LANChat managed discovery
// server, for networks where mDNS cannot cross segment or VLAN boundaries.
// It coordinates discovery and presence only: it never carries, stores or
// relays chat messages, files or any other peer-to-peer traffic.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/discoverysrv"
	"github.com/milad-raeisi/LANChat/internal/managedapi"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// Exit codes.
const (
	exitOK      = 0
	exitFailure = 1 // runtime failure, or unhealthy for healthcheck
	exitUsage   = 2 // invalid command line or configuration
)

const prog = "lanchat-discovery"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

func run(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "-version", "--version":
			cmd, args = "version", args[1:]
		case "-h", "-help", "--help":
			cmd, args = "help", args[1:]
		default:
			if !strings.HasPrefix(args[0], "-") {
				cmd, args = args[0], args[1:]
			}
		}
	}
	switch cmd {
	case "serve":
		return cmdServe(args, stderr, lookupEnv)
	case "fingerprint":
		return cmdFingerprint(args, stdout, stderr, lookupEnv)
	case "healthcheck":
		return cmdHealthcheck(args, stdout, stderr, lookupEnv)
	case "version":
		fmt.Fprintf(stdout, "%s %s\n", prog, buildinfo.Long())
		return exitOK
	case "help":
		if len(args) > 0 && args[0] != "help" && args[0] != "version" {
			return run([]string{args[0], "-h"}, stdout, stderr, lookupEnv)
		}
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n\n", prog, cmd)
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%[1]s - optional LANChat managed discovery server

Coordinates discovery and presence for LANChat on segmented networks
(VLANs, routed subnets) where mDNS cannot reach. It never carries, stores
or relays chat messages or files; peers still connect to each other
directly on their LANChat port.

Usage:
  %[1]s [serve] [flags]       run the server (default command)
  %[1]s fingerprint [flags]   print the certificate fingerprint clients pin
  %[1]s healthcheck [flags]   check a running server (exit 0 healthy, 1 not)
  %[1]s version               print version information
  %[1]s help [command]        show help

Run '%[1]s help <command>' for the flags of a command.
Settings come from built-in defaults, then --config FILE (TOML), then
%[2]s* environment variables, then flags.
Exit codes: 0 success, 1 runtime failure, 2 usage or configuration error.
`, prog, envPrefix)
}

func newFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(prog+" "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s %s [flags]\n\n%s\n\nFlags:\n", prog, name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags returns an exit code when the command should stop (help or a
// usage error), or -1 to continue.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer) int {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n", prog, fs.Arg(0))
		return exitUsage
	}
	return -1
}

func printConfigError(stderr io.Writer, err error) {
	lines := strings.Split(err.Error(), "\n")
	if len(lines) == 1 {
		fmt.Fprintf(stderr, "%s: %s\n", prog, lines[0])
		return
	}
	fmt.Fprintf(stderr, "%s: invalid configuration:\n", prog)
	for _, l := range lines {
		fmt.Fprintf(stderr, "  - %s\n", l)
	}
}

// ---- serve -------------------------------------------------------------------

func cmdServe(args []string, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := newFlagSet("serve", "Run the managed discovery server until SIGINT or SIGTERM.", stderr)
	cf := registerConfigFlags(fs, nil)
	if code := parseFlags(fs, args, stderr); code >= 0 {
		return code
	}
	cfg, err := cf.resolve(lookupEnv)
	if err != nil {
		printConfigError(stderr, err)
		return exitUsage
	}
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		printConfigError(stderr, err)
		return exitUsage
	}

	log, closer, err := cfg.OpenLogger(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s: open log: %v\n", prog, err)
		return exitFailure
	}
	defer closer.Close()

	srv, err := discoverysrv.New(cfg, log)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", prog, err)
		return exitFailure
	}
	if err := srv.Listen(); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", prog, err)
		return exitFailure
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	policy := fmt.Sprintf("authorized peers file (%d peers)", srv.AuthorizedCount())
	if cfg.AllowAny {
		policy = "allow_any"
		log.Warn("allow_any is enabled: any LANChat identity that can reach this server can register and see the directory")
	}
	log.Info("lanchat-discovery started",
		"version", buildinfo.Short(), "listen", srv.Addr().String(), "fingerprint", srv.Fingerprint(),
		"authorization", policy, "allowed_cidrs", strings.Join(cfg.AllowedCIDRs, ","),
		"presence_ttl", cfg.PresenceTTL.String(), "max_peers", cfg.MaxPeers)
	if cfg.LogFile != "" {
		fmt.Fprintf(stderr, "%s: listening on %s (fingerprint %s); logging to %s\n", prog, srv.Addr(), srv.Fingerprint(), cfg.LogFile)
	}

	if err := srv.Serve(ctx); err != nil {
		log.Error("server failed", "err", err)
		fmt.Fprintf(stderr, "%s: %v\n", prog, err)
		return exitFailure
	}
	log.Info("lanchat-discovery stopped")
	return exitOK
}

// ---- fingerprint -----------------------------------------------------------

func cmdFingerprint(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := newFlagSet("fingerprint",
		"Print the SHA-256 fingerprint of the server certificate's public key (SPKI),\n"+
			"which LANChat clients pin with managed_server_fingerprint. Creates the server\n"+
			"identity if it does not exist yet, so it can be run before the first start.",
		stderr)
	cf := registerConfigFlags(fs, []string{"identity_file", "tls_cert_file", "tls_key_file"})
	quiet := fs.Bool("quiet", false, "print only the 64-hex-digit fingerprint")
	if code := parseFlags(fs, args, stderr); code >= 0 {
		return code
	}
	cfg, err := cf.resolve(lookupEnv)
	if err != nil {
		printConfigError(stderr, err)
		return exitUsage
	}
	sc, err := discoverysrv.LoadServerCertificate(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", prog, err)
		return exitFailure
	}
	if sc.Created {
		fmt.Fprintf(stderr, "%s: created a new server identity at %s\n", prog, sc.Source)
	}
	if *quiet {
		fmt.Fprintln(stdout, sc.Fingerprint)
		return exitOK
	}
	fmt.Fprintf(stdout, `Server certificate fingerprint (SHA-256 of the public key, SPKI)
source: %s

  %s
  %s

Add to each LANChat client's config.toml, in the [discovery] section:

  managed_server_fingerprint = "%s"

Compare it with the operator over a trusted channel before using it.
`, sc.Source, sc.Fingerprint, identity.FormatFingerprint(sc.Fingerprint), sc.Fingerprint)
	return exitOK
}

// ---- healthcheck -----------------------------------------------------------

func cmdHealthcheck(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := newFlagSet("healthcheck",
		"Check that a server answers on /healthz (for Docker HEALTHCHECK). The server\n"+
			"certificate is not verified: this only checks liveness of a local server.",
		stderr)
	addr := fs.String("addr", defaultHealthAddr(lookupEnv), "server address host:port (default derived from "+envPrefix+"LISTEN)")
	timeout := fs.Duration("timeout", 5*time.Second, "overall timeout")
	if code := parseFlags(fs, args, stderr); code >= 0 {
		return code
	}
	if _, _, err := net.SplitHostPort(*addr); err != nil {
		fmt.Fprintf(stderr, "%s: --addr %q must be host:port\n", prog, *addr)
		return exitUsage
	}
	tr := &http.Transport{
		// Liveness only: no client certificate, no server verification.
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, //nolint:gosec // liveness probe of a local server
		Proxy:             nil,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: *timeout}
	res, err := client.Get("https://" + *addr + managedapi.PathHealth)
	if err != nil {
		fmt.Fprintf(stderr, "%s: unhealthy: %v\n", prog, err)
		return exitFailure
	}
	defer res.Body.Close()
	var h struct {
		Status string `json:"status"`
		Peers  int    `json:"peers"`
	}
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode != http.StatusOK || json.Unmarshal(data, &h) != nil || h.Status != "ok" {
		fmt.Fprintf(stderr, "%s: unhealthy: HTTP %d\n", prog, res.StatusCode)
		return exitFailure
	}
	fmt.Fprintf(stdout, "ok (%d peers online)\n", h.Peers)
	return exitOK
}

// defaultHealthAddr derives a local address from LANCHAT_DISCOVERY_LISTEN.
func defaultHealthAddr(lookupEnv func(string) (string, bool)) string {
	listen := discoverysrv.DefaultListen
	if v, ok := lookupEnv(envPrefix + "LISTEN"); ok && strings.TrimSpace(v) != "" {
		listen = strings.TrimSpace(v)
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(discoverysrv.DefaultPort))
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
