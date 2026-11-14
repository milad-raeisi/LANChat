package node

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/security/tlsconf"
)

// refreshInterfaces re-reads the interface list and reports whether the
// selected interfaces or their addresses changed.
func (n *Node) refreshInterfaces() bool {
	list, err := netif.List()
	var sel []netif.Interface
	errText := ""
	if err != nil {
		errText = err.Error()
	} else if sel, err = netif.Select(list, n.cfg.Network.Interface); err != nil {
		errText = err.Error()
	}
	key := netif.StateKey(sel)
	n.mu.Lock()
	defer n.mu.Unlock()
	changed := key != n.netKey || errText != n.ifaceErr
	n.ifaces, n.ifaceErr, n.netKey = sel, errText, key
	if changed {
		n.netChanged = time.Now()
	}
	return changed
}

// networkMonitorLoop detects Wi-Fi reconnects, DHCP address changes and
// interface changes, then restarts discovery and retries peers at once.
func (n *Node) networkMonitorLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		if !n.refreshInterfaces() {
			continue
		}
		st := n.NetworkStatus()
		n.log.Info("network changed", "interfaces", netif.Names(st.Interfaces), "error", st.InterfaceError)
		n.restartDiscovery()
		n.RefreshDiscovery()
		text := "Network changed; rediscovering peers."
		if st.InterfaceError != "" {
			text = "Network unavailable: " + st.InterfaceError
		}
		n.emit(Event{Kind: EventNetwork, Text: text})
	}
}

func (n *Node) localAddrs() []netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []netip.Addr
	for _, it := range n.ifaces {
		for _, a := range it.Addrs {
			if a.IP.Is6() && a.IP.IsLinkLocalUnicast() {
				continue // meaningless to a server on another segment
			}
			if (a.IP.Is4() && n.cfg.Network.EnableIPv4) || (a.IP.Is6() && n.cfg.Network.EnableIPv6) {
				out = append(out, a.IP)
			}
		}
	}
	return out
}

func (n *Node) buildDiscoverers() []discovery.Discoverer {
	if n.opts.Discoverers != nil {
		return n.opts.Discoverers
	}
	n.mu.Lock()
	self := discovery.Self{PeerID: n.id.ID(), DisplayName: n.name, DeviceName: n.device, Port: n.port,
		ProtocolVersion: buildinfo.ProtocolVersion, Capabilities: Capabilities}
	ifaceNames := netif.Names(n.ifaces)
	n.mu.Unlock()
	refresh := n.cfg.RefreshInterval()
	var out []discovery.Discoverer
	if n.cfg.Discovery.MDNSEnabled {
		out = append(out, discovery.NewMDNS(self, ifaceNames, refresh, n.log.With("component", "mdns")))
	}
	if len(n.cfg.Discovery.StaticPeers) > 0 {
		out = append(out, discovery.NewStatic(n.cfg.Discovery.StaticPeers, refresh, n.log.With("component", "static")))
	}
	if srv := n.cfg.Discovery.ManagedServer; srv != "" {
		host, _, _ := net.SplitHostPort(srv)
		tc, err := tlsconf.DiscoveryClientConfig(n.id, host, n.cfg.Discovery.ManagedServerFingerprint, n.cfg.Discovery.ManagedCAFile)
		if err != nil {
			n.log.Error("managed discovery disabled", "err", err)
			n.notice("error", "Managed discovery is disabled: %v", err)
		} else {
			out = append(out, discovery.NewManaged(srv, tc, self, n.localAddrs, refresh, n.log.With("component", "managed")))
		}
	}
	return out
}

func (n *Node) startDiscovery() {
	discs := n.buildDiscoverers()
	ctx, cancel := context.WithCancel(n.ctx)
	n.mu.Lock()
	n.discoverers = discs
	n.discCancel = cancel
	n.mu.Unlock()
	for _, d := range discs {
		d := d
		n.discWG.Add(1)
		go func() {
			defer n.discWG.Done()
			for ctx.Err() == nil {
				err := d.Run(ctx, n.discEvents)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					n.log.Warn("discovery stopped; retrying", "mechanism", d.Name(), "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Second):
				}
			}
		}()
	}
}

func (n *Node) restartDiscovery() {
	if n.opts.Discoverers != nil {
		return // injected discoverers are not interface-bound
	}
	n.mu.Lock()
	cancel := n.discCancel
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	waitTimeout(&n.discWG, 3*time.Second)
	if n.ctx.Err() == nil {
		n.startDiscovery()
	}
}
