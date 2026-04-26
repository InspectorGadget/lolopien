#!/bin/bash
# lolopien — WireGuard VPN server bootstrap script
# Run as EC2 user data on Ubuntu 22.04 LTS.
# After boot, retrieve the public key and store the private key in Secrets Manager.
set -euo pipefail

# ── 1. Install WireGuard ──────────────────────────────────────────────────────
apt-get update -y
apt-get install -y wireguard wireguard-tools iptables

# ── 2. Kernel IP forwarding ───────────────────────────────────────────────────
cat >> /etc/sysctl.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -p

# ── 3. Generate server keypair ────────────────────────────────────────────────
wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
chmod 600 /etc/wireguard/private.key /etc/wireguard/public.key

# ── 4. Write initial wg0.conf ────────────────────────────────────────────────
# The controller will overwrite this via SSM on first device registration.
# Adjust the Address subnet if you chose something other than 10.8.0.0/24.
PRIVATE_KEY=$(cat /etc/wireguard/private.key)
# Detect the primary network interface (ens5 on Nitro, eth0 on older instances)
IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.8.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${IFACE} -j MASQUERADE
EOF
chmod 600 /etc/wireguard/wg0.conf

# ── 5. Enable and start WireGuard ─────────────────────────────────────────────
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# ── 6. Ensure SSM agent is running ────────────────────────────────────────────
# Ubuntu 22.04 AMIs ship with snap-based SSM agent.
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent || true
systemctl start  snap.amazon-ssm-agent.amazon-ssm-agent || true

# ── 7. Write keypair summary to a known location for retrieval ────────────────
echo "=== WireGuard server keypair ==="
echo "Public key:  $(cat /etc/wireguard/public.key)"
echo "Private key: (stored in /etc/wireguard/private.key — push to Secrets Manager)"
