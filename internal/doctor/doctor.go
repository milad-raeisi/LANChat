// Package doctor implements `lanchat doctor`: local diagnostics that
// separate the stages of LANChat networking so users can see exactly where a
// problem lies:
//
//	socket initialisation → service advertisement → discovery of another
//	instance → authenticated (TLS) connectivity
//
// Output never contains private keys or other secrets.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/security/tlsconf"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

// Status of one check.
type Status string

// Check statuses.
const (
	Pass Status = "PASS"
	Warn Status = "WARN"
	Fail Status = "FAIL"
	Info Status = "INFO"
	Skip Status = "SKIP"
)

// Options configures a diagnostic run.
type Options struct {
	Dirs        platform.Dirs
	Verbose     bool
	Browse      time.Duration
	NetworkOnly bool
}

type reporter struct {
	out      io.Writer
	verbose  bool
	failures int
	warnings int
}

func (r *reporter) add(s Status, name, detail string) {
	if s == Fail {
		r.failures++
	}
	if s == Warn {
		r.warnings++
	}
	line := fmt.Sprintf("[%s] %s", s, name)
	if detail != "" {
		line += " – " + detail
	}
	fmt.Fprintln(r.out, line)
}

func (r *reporter) detail(format string, args ...any) {
	if r.verbose {
		fmt.Fprintf(r.out, "       "+format+"\n", args...)
	}
}

func (r *reporter) hint(format string, args ...any) {
	fmt.Fprintf(r.out, "       ↳ "+format+"\n", args...)
}

// Run executes the diagnostics, writes a report and returns the number of
// failed checks.
func Run(ctx context.Context, opts Options, out io.Writer) int {
	if opts.Browse <= 0 {
		opts.Browse = 4 * time.Second
	}
	r := &reporter{out: out, verbose: opts.Verbose}
	title := "LANChat Diagnostics"
	if opts.NetworkOnly {
		title = "LANChat Network Diagnostics"
	}
	fmt.Fprintf(out, "%s  (%s %s, %s/%s)\n\n", title, buildinfo.AppName, buildinfo.Short(), runtime.GOOS, runtime.GOARCH)

	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		r.add(Pass, "Operating system supported", runtime.GOOS+"/"+runtime.GOARCH)
	default:
		r.add(Warn, "Operating system", runtime.GOOS+" is not an officially supported platform")
	}

	// Configuration.
	cfg := config.Default()
	cfgPath := opts.Dirs.ConfigFile()
	loaded, res, err := config.Load(cfgPath)
	configured := false
	switch {
	case errors.Is(err, config.ErrNotFound):
		r.add(Fail, "Configuration", "not found at "+cfgPath)
		r.hint("run `lanchat` once to complete the setup wizard")
	case err != nil:
		r.add(Fail, "Configuration", err.Error())
	default:
		cfg = loaded
		if verr := cfg.Validate(); verr != nil {
			r.add(Fail, "Configuration valid", cfgPath)
			for _, line := range strings.Split(verr.Error(), "\n") {
				r.hint("%s", strings.TrimSpace(strings.TrimPrefix(line, "  - ")))
			}
		} else {
			configured = true
			r.add(Pass, "Configuration valid", cfgPath)
		}
		for _, k := range res.UnknownKeys {
			r.add(Warn, "Unknown configuration key", k+" (ignored)")
		}
	}

	running := platform.IsLocked(opts.Dirs.LockFile())
	if running {
		pid := platform.HolderPID(opts.Dirs.LockFile())
		r.add(Info, "LANChat is running", "PID "+strconv.Itoa(pid)+"; checks that would disturb it are skipped")
	}

	// Identity.
	id, err := identity.Load(opts.Dirs.IdentityFile())
	switch {
	case errors.Is(err, identity.ErrNoIdentity):
		r.add(Fail, "Local identity", "no identity key yet")
		r.hint("run `lanchat` to create one")
	case err != nil:
		r.add(Fail, "Local identity", err.Error())
	default:
		r.add(Pass, "Local identity loaded", "peer ID "+string(id.ID()))
		r.detail("fingerprint %s", identity.FormatFingerprint(id.Fingerprint()))
		if perr := platform.CheckPrivateFile(opts.Dirs.IdentityFile()); perr != nil {
			r.add(Warn, "Identity key permissions", perr.Error())
		}
	}

	// Interfaces.
	list, err := netif.List()
	var selected []netif.Interface
	if err != nil {
		r.add(Fail, "Network interfaces", err.Error())
	} else {
		selected, err = netif.Select(list, cfg.Network.Interface)
		if err != nil {
			r.add(Fail, "Network interface available", err.Error())
			r.hint("connect to Wi-Fi or Ethernet; on VPN-only machines choose an interface with network.interface")
		} else {
			var parts []string
			for _, it := range selected {
				var a []string
				for _, ad := range it.Addrs {
					a = append(a, ad.IP.String())
				}
				parts = append(parts, it.Name+" ("+strings.Join(a, ", ")+")")
			}
			r.add(Pass, "Network interface available", strings.Join(parts, "; "))
		}
		if opts.Verbose {
			for _, it := range list {
				mark := " "
				if contains(netif.Names(selected), it.Name) {
					mark = "*"
				}
				r.detail("%s %-12s score %4d  %s", mark, it.Name, it.Score, it.Summary())
			}
		}
	}

	// Listener.
	network, addr := node.ListenAddress(cfg.Network)
	if running {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Network.Port)), 2*time.Second)
		if err != nil {
			r.add(Warn, "TCP listener", fmt.Sprintf("LANChat is running but 127.0.0.1:%d did not accept a connection: %v", cfg.Network.Port, err))
		} else {
			_ = c.Close()
			r.add(Pass, "TCP listener initialized", fmt.Sprintf("the running instance accepts connections on port %d", cfg.Network.Port))
		}
	} else if ln, err := net.Listen(network, addr); err != nil {
		r.add(Fail, "TCP listener", fmt.Sprintf("cannot listen on %s: %v", addr, err))
		r.hint("another program uses the port; choose a different network.port")
	} else {
		_ = ln.Close()
		r.add(Pass, "TCP listener initialized", addr+" can be bound")
	}

	// Database.
	if !opts.NetworkOnly {
		dbPath := cfg.DatabasePath(opts.Dirs)
		if _, statErr := os.Stat(dbPath); errors.Is(statErr, os.ErrNotExist) {
			r.add(Info, "SQLite database", "not created yet (LANChat creates it on first launch)")
		} else if st, err := storage.Open(ctx, dbPath); err != nil {
			r.add(Fail, "SQLite database", err.Error())
			if errors.Is(err, storage.ErrCorrupt) {
				r.hint("move %s aside (LANChat creates a new one) or restore a backup made with `lanchat data backup`", dbPath)
			}
		} else {
			if err := st.QuickCheck(ctx); err != nil {
				r.add(Fail, "SQLite database", err.Error())
			} else if s, err := st.Stats(ctx); err == nil {
				r.add(Pass, "SQLite database accessible", fmt.Sprintf("%d peers (%d trusted), %d messages, %d undelivered", s.Peers, s.TrustedPeers, s.Messages, s.PendingDeliveries))
				r.detail("path %s", dbPath)
			}
			_ = st.Close()
		}
	}

	// Discovery stages.
	var probe discovery.ProbeResult
	if cfg.Discovery.MDNSEnabled {
		if err := discovery.ProbeMulticast(); err != nil {
			r.add(Fail, "Multicast socket", err.Error())
			r.hint("UDP port 5353 may be blocked or owned exclusively by another program")
		} else {
			r.add(Pass, "Multicast socket initialized", "this alone does not prove discovery works")
			var exclude identity.PeerID
			if id != nil {
				exclude = id.ID()
			}
			fmt.Fprintf(out, "       … announcing a probe and browsing for %s\n", opts.Browse)
			probe = discovery.ProbeAnnounceAndBrowse(ctx, opts.Browse, max(cfg.Network.Port, 1), exclude)
			switch {
			case probe.Err != nil:
				r.add(Fail, "Service advertisement", probe.Err.Error())
			case probe.SelfSeen:
				r.add(Pass, "Service advertisement", "a test announcement was published and received back on this host")
			case probe.Announced:
				r.add(Warn, "Service advertisement", "announced, but not observed by a local browse (multicast loopback may be disabled)")
			}
			if len(probe.Peers) == 0 {
				r.add(Warn, "No peers discovered", "no other LANChat instance answered within "+opts.Browse.String())
				r.add(Info, "Check network isolation or peer availability", "")
				r.hint("are other users running LANChat on the same network segment?")
				r.hint("guest/hotel Wi-Fi often isolates clients; mDNS does not cross routers or VLANs")
				r.hint("in segmented networks use managed discovery or [discovery] static_peers")
			} else {
				r.add(Pass, "Peers discovered", fmt.Sprintf("%d other LANChat instance(s)", len(probe.Peers)))
				for _, p := range probe.Peers {
					var a []string
					for _, ap := range p.Addrs {
						a = append(a, ap.String())
					}
					r.detail("%s #%s via %s at %s", textsafe.Line(p.DisplayName, 32), p.PeerID.Short(), p.Interface, strings.Join(a, ", "))
				}
			}
		}
	} else {
		r.add(Skip, "mDNS discovery", "disabled in configuration")
	}

	// Authenticated connectivity.
	switch {
	case id == nil || !configured:
		r.add(Skip, "Authenticated connectivity", "needs a valid configuration and identity")
	case running:
		r.add(Skip, "Authenticated connectivity", "skipped while LANChat is running (the app shows reachability per peer)")
	case len(probe.Peers) == 0 && len(cfg.Discovery.StaticPeers) == 0:
		r.add(Skip, "Authenticated connectivity", "no peer to test against")
	default:
		checkConnectivity(ctx, r, cfg, id, probe.Peers)
	}

	// Managed discovery.
	if cfg.Discovery.ManagedServer != "" && id != nil {
		checkManaged(ctx, r, cfg, id, selected, running)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Firewall notes:")
	for _, l := range platform.FirewallAdvice(cfg.Network.Port) {
		fmt.Fprintln(out, "  "+l)
	}
	fmt.Fprintln(out)
	switch {
	case r.failures > 0:
		fmt.Fprintf(out, "%d check(s) failed, %d warning(s). See docs/troubleshooting.md.\n", r.failures, r.warnings)
	case r.warnings > 0:
		fmt.Fprintf(out, "No failures, %d warning(s).\n", r.warnings)
	default:
		fmt.Fprintln(out, "All checks passed.")
	}
	return r.failures
}

func checkConnectivity(ctx context.Context, r *reporter, cfg config.Config, id *identity.Identity, peers []discovery.Advert) {
	tcfg, err := transport.NewConfig(id, func() protocol.Hello {
		return protocol.Hello{DisplayName: cfg.User.DisplayName, DeviceName: cfg.User.DeviceName, App: "lanchat-doctor"}
	}, cfg.ConnectionTimeout(), cfg.HeartbeatInterval())
	if err != nil {
		r.add(Fail, "Authenticated connectivity", err.Error())
		return
	}
	type target struct {
		name  string
		id    identity.PeerID
		addrs []string
	}
	var targets []target
	for _, p := range peers {
		var a []string
		for _, ap := range p.Addrs {
			a = append(a, ap.String())
		}
		targets = append(targets, target{textsafe.Line(p.DisplayName, 32), p.PeerID, a})
	}
	for _, s := range cfg.Discovery.StaticPeers {
		targets = append(targets, target{"static " + s, "", []string{s}})
	}
	if len(targets) > 3 {
		targets = targets[:3]
	}
	ok := 0
	for _, t := range targets {
		start := time.Now()
		s, err := transport.Dial(ctx, tcfg, t.addrs, t.id)
		if err != nil {
			var mm *transport.IdentityMismatchError
			if errors.As(err, &mm) {
				r.add(Fail, "Authenticated connectivity to "+t.name, "identity mismatch: the address answered with a different key")
			} else {
				r.add(Warn, "Authenticated connectivity to "+t.name, oneLine(err.Error()))
				r.hint("discovered but not reachable: a firewall may block TCP %s, or the networks are isolated", portOf(t.addrs))
			}
			continue
		}
		ok++
		r.add(Pass, "Authenticated connectivity to "+t.name, fmt.Sprintf("TLS 1.3 handshake in %s (peer %s)", time.Since(start).Round(time.Millisecond), s.PeerID().Short()))
		s.CloseWithError(protocol.CodeShuttingDown, "diagnostic connection")
	}
	_ = ok
}

func checkManaged(ctx context.Context, r *reporter, cfg config.Config, id *identity.Identity, selected []netif.Interface, running bool) {
	if running {
		r.add(Skip, "Managed discovery", "skipped while LANChat is running")
		return
	}
	host, _, _ := net.SplitHostPort(cfg.Discovery.ManagedServer)
	tc, err := tlsconf.DiscoveryClientConfig(id, host, cfg.Discovery.ManagedServerFingerprint, cfg.Discovery.ManagedCAFile)
	if err != nil {
		r.add(Fail, "Managed discovery", err.Error())
		return
	}
	var addrs []netip.Addr
	for _, it := range selected {
		for _, a := range it.Addrs {
			if !a.IP.IsLinkLocalUnicast() {
				addrs = append(addrs, a.IP)
			}
		}
	}
	m := discovery.NewManaged(cfg.Discovery.ManagedServer, tc,
		discovery.Self{PeerID: id.ID(), DisplayName: cfg.User.DisplayName, DeviceName: cfg.User.DeviceName, Port: max(cfg.Network.Port, 1),
			ProtocolVersion: buildinfo.ProtocolVersion},
		func() []netip.Addr { return addrs }, cfg.RefreshInterval(), logging.Discard())
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := m.Announce(cctx)
	if err != nil {
		r.add(Fail, "Managed discovery", oneLine(err.Error()))
		r.hint("check the server address, that TCP to it is allowed, and the pinned fingerprint")
		return
	}
	_ = m.Withdraw(cctx)
	r.add(Pass, "Managed discovery", fmt.Sprintf("registered with %s; %d other peer(s) listed; server saw us as %s",
		cfg.Discovery.ManagedServer, len(resp.Peers), resp.ObservedAddress))
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", "; ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func portOf(addrs []string) string {
	if len(addrs) == 0 {
		return "?"
	}
	_, p, _ := net.SplitHostPort(addrs[0])
	return p
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
