package discovery

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/brutella/dnssd"

	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

func TestParseBrowseEntry(t *testing.T) {
	id, _ := identity.Generate()
	e := dnssd.BrowseEntry{
		IPs:       []net.IP{net.ParseIP("fe80::1"), net.ParseIP("192.168.1.20"), net.ParseIP("127.0.0.1")},
		Port:      47777,
		IfaceName: "en0",
		Text:      map[string]string{"id": string(id.ID()), "name": "Maryam", "dev": "PC", "v": "1"},
	}
	a, ok := ParseBrowseEntry(e, time.Second)
	if !ok {
		t.Fatal("valid entry rejected")
	}
	if a.PeerID != id.ID() || a.DisplayName != "Maryam" || a.ProtocolVersion != 1 {
		t.Fatalf("fields: %+v", a)
	}
	if len(a.Addrs) != 2 || a.Addrs[0].String() != "192.168.1.20:47777" || a.Addrs[1].Addr().Zone() != "en0" {
		t.Fatalf("addresses not sorted/filtered/zoned: %v", a.Addrs)
	}
	for _, bad := range []dnssd.BrowseEntry{
		{IPs: e.IPs, Port: 47777, Text: map[string]string{"id": "forged"}},
		{IPs: e.IPs, Port: 0, Text: e.Text},
		{IPs: []net.IP{net.ParseIP("127.0.0.1")}, Port: 47777, Text: e.Text},
	} {
		if _, ok := ParseBrowseEntry(bad, time.Second); ok {
			t.Errorf("invalid entry accepted: %+v", bad)
		}
	}
}

func TestStaticResolvesAddresses(t *testing.T) {
	s := NewStatic([]string{"192.168.1.30:47777", "localhost:47778", "bad"}, time.Hour, logging.Discard())
	events := make(chan Event, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx, events); close(done) }()
	got := map[string]Advert{}
	timeout := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case ev := <-events:
			got[ev.Advert.Key] = ev.Advert
		case <-timeout:
			t.Fatalf("got %d adverts", len(got))
		}
	}
	cancel()
	<-done
	a := got["static:192.168.1.30:47777"]
	if a.PeerID != "" || len(a.Addrs) != 1 || a.Addrs[0] != netip.MustParseAddrPort("192.168.1.30:47777") {
		t.Fatalf("static advert: %+v", a)
	}
	if s.Status().LastError == "" {
		t.Fatal("invalid entry should be reported in status")
	}
}

func TestSortAddrs(t *testing.T) {
	in := []netip.AddrPort{
		netip.MustParseAddrPort("[fe80::1%en0]:1"),
		netip.MustParseAddrPort("[fd00::1]:1"),
		netip.MustParseAddrPort("8.8.8.8:1"),
		netip.MustParseAddrPort("10.0.0.1:1"),
		netip.MustParseAddrPort("10.0.0.1:1"),
	}
	out := SortAddrs(in)
	if len(out) != 4 || out[0].Addr().String() != "10.0.0.1" || out[3].Addr().Zone() != "en0" {
		t.Fatalf("SortAddrs = %v", out)
	}
}

// TestMDNSLoopback announces and browses on this host. Multicast is often
// unavailable in CI containers and sandboxes, so the test skips rather than
// fails when nothing is heard.
func TestMDNSLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("mDNS test skipped in -short mode")
	}
	if err := ProbeMulticast(); err != nil {
		t.Skipf("multicast unavailable: %v", err)
	}
	a, _ := identity.Generate()
	b, _ := identity.Generate()
	ma := NewMDNS(Self{PeerID: a.ID(), DisplayName: "A", Port: 41001, ProtocolVersion: 1}, nil, 2*time.Second, logging.Discard())
	mb := NewMDNS(Self{PeerID: b.ID(), DisplayName: "B", Port: 41002, ProtocolVersion: 1}, nil, 2*time.Second, logging.Discard())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ea := make(chan Event, 64)
	eb := make(chan Event, 64)
	go func() { _ = ma.Run(ctx, ea) }()
	go func() { _ = mb.Run(ctx, eb) }()
	for {
		select {
		case ev := <-ea:
			if ev.Advert.PeerID == b.ID() && !ev.Removed {
				if ev.Advert.DisplayName != "B" {
					t.Fatalf("wrong name %q", ev.Advert.DisplayName)
				}
				return
			}
		case <-eb:
		case <-ctx.Done():
			t.Skip("no mDNS traffic observed on this host (multicast may be filtered)")
		}
	}
}
