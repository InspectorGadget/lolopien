package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type Keypair struct {
	PrivateKey string // base64-encoded, 32 bytes
	PublicKey  string // base64-encoded, 32 bytes
}

// GenerateKeypair generates a fresh WireGuard Curve25519 keypair.
func GenerateKeypair() (Keypair, error) {
	var privRaw [32]byte
	if _, err := rand.Read(privRaw[:]); err != nil {
		return Keypair{}, fmt.Errorf("generating random private key: %w", err)
	}

	// Clamp per WireGuard / Curve25519 spec
	privRaw[0] &= 248
	privRaw[31] = (privRaw[31] & 127) | 64

	pubRaw, err := curve25519.X25519(privRaw[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, fmt.Errorf("deriving public key: %w", err)
	}

	return Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(privRaw[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pubRaw),
	}, nil
}

// ClientConfigParams holds everything needed to render a client .conf file.
type ClientConfigParams struct {
	DevicePrivateKey string // base64
	DeviceVpnIP      string // e.g. "10.8.0.5"
	SubnetMask       string // e.g. "24" — derived from the server's CIDR
	ServerPublicKey  string // base64
	ServerEndpoint   string // e.g. "1.2.3.4:51820"
	DNS              string // default "1.1.1.1" if empty
}

// ClientConfig renders a WireGuard .conf file the user imports into any
// WireGuard client. AllowedIPs = 0.0.0.0/0 routes all traffic through the VPN.
func ClientConfig(p ClientConfigParams) string {
	dns := p.DNS
	if dns == "" {
		dns = "1.1.1.1"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.DevicePrivateKey)
	fmt.Fprintf(&b, "Address = %s/%s\n", p.DeviceVpnIP, p.SubnetMask)
	fmt.Fprintf(&b, "DNS = %s\n", dns)
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", p.ServerPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", p.ServerEndpoint)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	return b.String()
}

// ServerConfigParams holds everything needed to render a server wg0.conf.
type ServerConfigParams struct {
	ServerPrivateKey string // base64 — fetched from Secrets Manager
	ServerVpnIP      string // e.g. "10.8.0.1"
	SubnetMask       string // e.g. "24"
	ListenPort       int    // default 51820
	Peers            []PeerEntry
}

// PeerEntry represents a single [Peer] block in the server config.
type PeerEntry struct {
	PublicKey string // device public key, base64
	VpnIP     string // assigned VPN IP, e.g. "10.8.0.5"
}

// ServerConfig renders the full wg0.conf including wg-quick directives
// (Address, PostUp, PostDown). Written to /etc/wireguard/wg0.conf on the
// EC2 instance for persistence across reboots.
func ServerConfig(p ServerConfigParams) string {
	port := p.ListenPort
	if port == 0 {
		port = 51820
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.ServerPrivateKey)
	fmt.Fprintf(&b, "Address = %s/%s\n", p.ServerVpnIP, p.SubnetMask)
	fmt.Fprintf(&b, "ListenPort = %d\n", port)
	fmt.Fprintf(&b, "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}' | head -1) -j MASQUERADE\n")
	fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}' | head -1) -j MASQUERADE\n")

	for _, peer := range p.Peers {
		fmt.Fprintf(&b, "\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", peer.VpnIP)
	}
	return b.String()
}

// SyncConfConfig renders a stripped-down config containing only kernel-level
// WireGuard directives. Used with `wg syncconf` which rejects wg-quick
// directives like Address, PostUp, and PostDown.
func SyncConfConfig(p ServerConfigParams) string {
	port := p.ListenPort
	if port == 0 {
		port = 51820
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.ServerPrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", port)

	for _, peer := range p.Peers {
		fmt.Fprintf(&b, "\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", peer.VpnIP)
	}
	return b.String()
}
