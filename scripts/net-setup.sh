#!/bin/bash
# Set up TAP device + bridge + DHCP/DNS + NAT for rvOS networking.
# Must be run as root (or via sudo).
#
# Creates (if not already present):
#   rvos-tap0  — TAP device owned by $SUDO_USER (or $USER)
#   rvos-br0   — bridge with IP 10.0.2.2/24
#   dnsmasq    — DHCP + DNS server on the bridge (if installed)
#   iptables   — NAT masquerade for internet access (if installed)
#
# The guest obtains its IP via DHCP (range 10.0.2.10–10.0.2.200).
# If DHCP fails, the guest falls back to static 10.0.2.15/24.
#
# Idempotent — safe to run multiple times.

set -e

TAP=rvos-tap0
BR=rvos-br0
OWNER=${SUDO_USER:-$USER}
DNSMASQ_PID=/run/rvos-dnsmasq.pid
DNSMASQ_CONF=/tmp/rvos-dnsmasq.conf

# Create bridge if it doesn't exist
if ! ip link show "$BR" &>/dev/null; then
    ip link add "$BR" type bridge
    ip addr add 10.0.2.2/24 dev "$BR"
    ip link set "$BR" up
    echo "Created bridge $BR with IP 10.0.2.2/24"
else
    echo "Bridge $BR already exists"
fi

# Create TAP device if it doesn't exist
if ! ip link show "$TAP" &>/dev/null; then
    ip tuntap add dev "$TAP" mode tap user "$OWNER"
    ip link set "$TAP" master "$BR"
    ip link set "$TAP" up
    echo "Created TAP $TAP (owner=$OWNER)"
else
    echo "TAP $TAP already exists"
fi

# Enable IP forwarding (required for NAT)
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "Enabled IP forwarding"
fi

# Set up NAT so rvOS guests can reach the internet
if command -v iptables &>/dev/null; then
    # Masquerade outbound traffic from 10.0.2.0/24 (except to the bridge itself)
    iptables -t nat -C POSTROUTING -s 10.0.2.0/24 ! -o "$BR" -j MASQUERADE 2>/dev/null ||
      iptables -t nat -A POSTROUTING -s 10.0.2.0/24 ! -o "$BR" -j MASQUERADE
    # Allow forwarding from the bridge
    iptables -C FORWARD -i "$BR" -j ACCEPT 2>/dev/null ||
      iptables -A FORWARD -i "$BR" -j ACCEPT
    # Allow return traffic
    iptables -C FORWARD -o "$BR" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
      iptables -A FORWARD -o "$BR" -m state --state RELATED,ESTABLISHED -j ACCEPT
    echo "NAT configured (masquerade 10.0.2.0/24)"
else
    echo "WARNING: iptables not installed — no NAT (guests won't reach the internet)"
fi

# Discover upstream DNS server from systemd-resolved or /etc/resolv.conf
UPSTREAM_DNS=""
if command -v resolvectl &>/dev/null; then
    UPSTREAM_DNS=$(resolvectl status 2>/dev/null | sed -n 's/.*Current DNS Server: //p' | head -1)
fi
if [ -z "$UPSTREAM_DNS" ]; then
    # Fall back to first non-localhost nameserver in resolv.conf
    UPSTREAM_DNS=$(sed -n 's/^nameserver[[:space:]]\+//p' /etc/resolv.conf | grep -v '^127\.' | head -1)
fi
if [ -z "$UPSTREAM_DNS" ]; then
    # Last resort: use systemd-resolved stub (works if resolved is running)
    UPSTREAM_DNS="127.0.0.53"
fi

# Start dnsmasq DHCP + DNS server on the bridge (if not already running)
if command -v dnsmasq &>/dev/null; then
    if [ -f "$DNSMASQ_PID" ] && kill -0 "$(cat "$DNSMASQ_PID")" 2>/dev/null; then
        echo "dnsmasq already running (PID $(cat "$DNSMASQ_PID"))"
    else
        cat > "$DNSMASQ_CONF" <<EOF
interface=$BR
bind-interfaces
dhcp-range=10.0.2.10,10.0.2.200,255.255.255.0,1h
dhcp-option=option:router,10.0.2.2
dhcp-option=option:dns-server,10.0.2.2
server=$UPSTREAM_DNS
no-hosts
EOF
        dnsmasq -C "$DNSMASQ_CONF" --pid-file="$DNSMASQ_PID"
        echo "Started dnsmasq (PID $(cat "$DNSMASQ_PID"), DHCP 10.0.2.10–10.0.2.200, DNS→$UPSTREAM_DNS)"
    fi
else
    echo "WARNING: dnsmasq not installed — no DHCP server"
    echo "  Guest will fall back to static IP 10.0.2.15"
    echo "  Install: sudo apt install dnsmasq"
fi

echo "TAP=$TAP  BRIDGE=$BR  BRIDGE_IP=10.0.2.2/24  (owner=$OWNER)"
echo "Ready.  Run:  make run"
