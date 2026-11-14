package platform

import (
	"fmt"
	"runtime"
)

// FirewallAdvice explains, for the current operating system, what a user
// may need to allow so LANChat can discover peers and accept connections.
// LANChat itself never changes firewall or network settings.
func FirewallAdvice(port int) []string {
	return firewallAdviceFor(runtime.GOOS, port)
}

func firewallAdviceFor(goos string, port int) []string {
	switch goos {
	case "darwin":
		return []string{
			"macOS may ask whether your terminal app may find devices on local networks.",
			"Allow it (System Settings › Privacy & Security › Local Network), otherwise discovery cannot work.",
			"If the Application Firewall is enabled, allow incoming connections for lanchat when prompted.",
		}
	case "windows":
		return []string{
			"Windows Defender Firewall will ask whether lanchat may communicate on networks.",
			"Allow it on Private networks only. Your Wi-Fi/Ethernet profile must be set to Private for discovery",
			"(Settings › Network & Internet › your network › Network profile type).",
		}
	default:
		return []string{
			fmt.Sprintf("If a host firewall is active, allow UDP 5353 (mDNS) and TCP %d (LANChat).", port),
			fmt.Sprintf("  ufw:       sudo ufw allow 5353/udp && sudo ufw allow %d/tcp", port),
			fmt.Sprintf("  firewalld: sudo firewall-cmd --permanent --add-service=mdns --add-port=%d/tcp && sudo firewall-cmd --reload", port),
			"LANChat never changes firewall rules itself.",
		}
	}
}
