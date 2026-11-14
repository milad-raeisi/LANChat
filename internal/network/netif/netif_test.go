package netif

import (
	"net/netip"
	"testing"
)

func iface(name string, up, loop, mcast bool, addrs ...string) Interface {
	it := Interface{Name: name, Up: up, Loopback: loop, Multicast: mcast}
	for _, a := range addrs {
		it.Addrs = append(it.Addrs, Addr{IP: netip.MustParseAddr(a), Prefix: 24})
	}
	return Score(it)
}

func TestClassify(t *testing.T) {
	for _, n := range []string{"docker0", "br-1234", "veth9", "utun3", "awdl0", "vEthernet (WSL)", "VirtualBox Host-Only Network", "wg0", "tailscale0"} {
		if v, _ := Classify(n); !v {
			t.Errorf("%s should be virtual", n)
		}
	}
	for _, n := range []string{"en0", "eth0", "wlan0", "enp3s0", "Wi-Fi", "Ethernet"} {
		if v, note := Classify(n); v {
			t.Errorf("%s classified virtual (%s)", n, note)
		}
	}
}

func TestRecommendAndSelect(t *testing.T) {
	list := []Interface{
		iface("lo0", true, true, true, "127.0.0.1"),
		iface("docker0", true, false, true, "172.17.0.1"),
		iface("en0", true, false, true, "192.168.1.10", "fe80::1"),
		iface("en5", false, false, true, "10.0.0.5"),
		iface("utun2", true, false, true, "100.64.0.2"),
	}
	SortByScore(list)
	best := Recommend(list)
	if best == nil || best.Name != "en0" {
		t.Fatalf("recommended %+v", best)
	}
	sel, err := Select(list, "auto")
	if err != nil || len(sel) != 1 || sel[0].Name != "en0" {
		t.Fatalf("auto select: %v %v", Names(sel), err)
	}
	sel, err = Select(list, "docker0")
	if err != nil || sel[0].Name != "docker0" {
		t.Fatal("explicit virtual interface must be honoured")
	}
	if _, err := Select(list, "en5"); err == nil {
		t.Fatal("down interface selected")
	}
	if _, err := Select(list, "nope"); err == nil {
		t.Fatal("missing interface selected")
	}
	if _, err := Select(list[:0], "auto"); err == nil {
		t.Fatal("expected error with no interfaces")
	}
}

func TestStateKeyChanges(t *testing.T) {
	a := []Interface{iface("en0", true, false, true, "192.168.1.10")}
	b := []Interface{iface("en0", true, false, true, "192.168.1.11")}
	if StateKey(a) == StateKey(b) {
		t.Fatal("address change not detected")
	}
	if StateKey(a) != StateKey([]Interface{iface("en0", true, false, true, "192.168.1.10")}) {
		t.Fatal("state key not stable")
	}
}

func TestListRuns(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Skip("no interfaces in this environment")
	}
}
