// Package netif enumerates and classifies network interfaces so LANChat can
// pick a sensible LAN interface automatically and let advanced users choose
// one explicitly.
package netif

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Addr is one interface address.
type Addr struct {
	IP     netip.Addr
	Prefix int
}

func (a Addr) String() string { return fmt.Sprintf("%s/%d", a.IP, a.Prefix) }

// Interface describes a network interface and LANChat's assessment of it.
type Interface struct {
	Name         string
	Index        int
	MTU          int
	HardwareAddr string
	Up           bool
	Loopback     bool
	Multicast    bool
	PointToPoint bool
	Addrs        []Addr
	// Virtual is true for container, VM, VPN and similar adapters.
	Virtual bool
	// Note explains why an interface is virtual or unsuitable.
	Note string
	// Score ranks suitability for LAN chat; <= 0 means not recommended.
	Score int
}

// IPv4 returns the interface's IPv4 addresses.
func (i Interface) IPv4() []netip.Addr {
	var out []netip.Addr
	for _, a := range i.Addrs {
		if a.IP.Is4() {
			out = append(out, a.IP)
		}
	}
	return out
}

// IPv6 returns the interface's IPv6 addresses.
func (i Interface) IPv6() []netip.Addr {
	var out []netip.Addr
	for _, a := range i.Addrs {
		if a.IP.Is6() && !a.IP.Is4In6() {
			out = append(out, a.IP)
		}
	}
	return out
}

// Usable reports whether the interface can carry LAN discovery traffic.
func (i Interface) Usable() bool {
	return i.Up && !i.Loopback && i.Multicast && len(i.Addrs) > 0
}

// Summary is a one-line description.
func (i Interface) Summary() string {
	var addrs []string
	for _, a := range i.Addrs {
		addrs = append(addrs, a.IP.String())
	}
	s := i.Name
	if len(addrs) > 0 {
		s += " (" + strings.Join(addrs, ", ") + ")"
	}
	if i.Note != "" {
		s += " – " + i.Note
	}
	return s
}

// virtualPatterns maps name fragments (lowercase) to a human explanation.
var virtualPatterns = []struct{ prefix, contains, note string }{
	{prefix: "docker", note: "Docker bridge"},
	{prefix: "br-", note: "container bridge"},
	{prefix: "veth", note: "container virtual ethernet"},
	{prefix: "virbr", note: "libvirt bridge"},
	{prefix: "vmnet", note: "VMware adapter"},
	{prefix: "vboxnet", note: "VirtualBox adapter"},
	{prefix: "utun", note: "VPN tunnel"},
	{prefix: "tun", note: "tunnel"},
	{prefix: "tap", note: "TAP adapter"},
	{prefix: "wg", note: "WireGuard"},
	{prefix: "tailscale", note: "Tailscale"},
	{prefix: "zt", note: "ZeroTier"},
	{prefix: "awdl", note: "Apple Wireless Direct Link"},
	{prefix: "llw", note: "Apple low-latency WLAN"},
	{prefix: "anpi", note: "Apple internal network"},
	{prefix: "ap1", note: "Wi-Fi access point mode"},
	{prefix: "bridge", note: "bridge / Internet Sharing"},
	{prefix: "gif", note: "IPv6 tunnel"},
	{prefix: "stf", note: "6to4 tunnel"},
	{prefix: "lxcbr", note: "LXC bridge"},
	{prefix: "lxdbr", note: "LXD bridge"},
	{prefix: "cni", note: "Kubernetes CNI"},
	{prefix: "flannel", note: "Kubernetes overlay"},
	{prefix: "cali", note: "Calico"},
	{prefix: "podman", note: "Podman bridge"},
	{contains: "vethernet", note: "Hyper-V / WSL virtual switch"},
	{contains: "hyper-v", note: "Hyper-V adapter"},
	{contains: "virtualbox", note: "VirtualBox adapter"},
	{contains: "vmware", note: "VMware adapter"},
	{contains: "bluetooth", note: "Bluetooth network"},
	{contains: "wireguard", note: "WireGuard"},
	{contains: "zerotier", note: "ZeroTier"},
	{contains: "npcap", note: "packet capture loopback"},
	{contains: "pseudo-interface", note: "loopback"},
	{contains: "tap-windows", note: "TAP adapter"},
	{contains: "openvpn", note: "OpenVPN"},
}

// Classify reports whether an interface name looks virtual.
func Classify(name string) (virtual bool, note string) {
	n := strings.ToLower(name)
	for _, p := range virtualPatterns {
		if p.prefix != "" && strings.HasPrefix(n, p.prefix) {
			return true, p.note
		}
		if p.contains != "" && strings.Contains(n, p.contains) {
			return true, p.note
		}
	}
	return false, ""
}

// List returns all interfaces with classification and scores, best first.
func List() ([]Interface, error) {
	sys, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate network interfaces: %w", err)
	}
	out := make([]Interface, 0, len(sys))
	for _, s := range sys {
		it := Interface{
			Name:         s.Name,
			Index:        s.Index,
			MTU:          s.MTU,
			HardwareAddr: s.HardwareAddr.String(),
			Up:           s.Flags&net.FlagUp != 0 && s.Flags&net.FlagRunning != 0,
			Loopback:     s.Flags&net.FlagLoopback != 0,
			Multicast:    s.Flags&net.FlagMulticast != 0,
			PointToPoint: s.Flags&net.FlagPointToPoint != 0,
		}
		if addrs, err := s.Addrs(); err == nil {
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				ones, _ := ipn.Mask.Size()
				it.Addrs = append(it.Addrs, Addr{IP: ip.Unmap(), Prefix: ones})
			}
		}
		out = append(out, Score(it))
	}
	SortByScore(out)
	return out, nil
}

// Score classifies and scores an interface.
func Score(it Interface) Interface {
	it.Virtual, it.Note = Classify(it.Name)
	score := 0
	switch {
	case it.Loopback:
		it.Note, score = "loopback", -100
	case !it.Up:
		if it.Note == "" {
			it.Note = "down"
		}
		score = -100
	case !it.Multicast:
		if it.Note == "" {
			it.Note = "no multicast support"
		}
		score = -50
	case len(it.Addrs) == 0:
		if it.Note == "" {
			it.Note = "no addresses"
		}
		score = -50
	default:
		score = 10
		for _, a := range it.Addrs {
			switch {
			case a.IP.Is4() && a.IP.IsPrivate():
				score += 50
			case a.IP.Is4() && a.IP.IsLinkLocalUnicast():
				score += 2
			case a.IP.Is4():
				score += 20
			case a.IP.Is6() && a.IP.IsPrivate(): // ULA
				score += 5
			case a.IP.Is6() && a.IP.IsLinkLocalUnicast():
				score += 1
			}
		}
		if it.PointToPoint {
			score -= 40
			if it.Note == "" {
				it.Note = "point-to-point link (VPN?)"
			}
		}
		if it.Virtual {
			score -= 80
		}
	}
	it.Score = score
	return it
}

// SortByScore orders interfaces best first, then by name.
func SortByScore(list []Interface) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Score != list[j].Score {
			return list[i].Score > list[j].Score
		}
		return list[i].Name < list[j].Name
	})
}

// Recommend returns the best interface, or nil when none is suitable.
func Recommend(list []Interface) *Interface {
	for i := range list {
		if list[i].Usable() && !list[i].Virtual && list[i].Score > 0 {
			return &list[i]
		}
	}
	return nil
}

// Select returns the interfaces LANChat should use for discovery. With
// "auto" every usable, non-virtual interface with a positive score is
// selected (multi-homed hosts announce on all LANs). A named interface is
// used exactly, even if virtual, because the user asked for it.
func Select(list []Interface, want string) ([]Interface, error) {
	if want == "" || want == "auto" {
		var out []Interface
		for _, it := range list {
			if it.Usable() && !it.Virtual && it.Score > 0 {
				out = append(out, it)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no usable LAN interface found; connect to a network or choose one with network.interface")
		}
		return out, nil
	}
	for _, it := range list {
		if it.Name == want {
			if !it.Up {
				return nil, fmt.Errorf("interface %s is down", want)
			}
			if len(it.Addrs) == 0 {
				return nil, fmt.Errorf("interface %s has no IP address", want)
			}
			return []Interface{it}, nil
		}
	}
	return nil, fmt.Errorf("interface %q not found (see `lanchat network interfaces`)", want)
}

// Names returns interface names.
func Names(list []Interface) []string {
	out := make([]string, len(list))
	for i, it := range list {
		out[i] = it.Name
	}
	return out
}

// StateKey summarises interface names and addresses so callers can detect
// network changes (Wi-Fi reconnects, DHCP renewals, cable changes).
func StateKey(list []Interface) string {
	var parts []string
	for _, it := range list {
		if !it.Up || it.Loopback {
			continue
		}
		var addrs []string
		for _, a := range it.Addrs {
			addrs = append(addrs, a.IP.String())
		}
		sort.Strings(addrs)
		parts = append(parts, it.Name+"="+strings.Join(addrs, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
