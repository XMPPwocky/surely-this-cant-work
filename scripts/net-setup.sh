#!/bin/bash
# Set up TAP device + bridge + DHCP server for rvOS networking.
# Must be run as root (or via sudo).
#
# Creates (if not already present):
#   rvos-tap0  — TAP device owned by $SUDO_USER (or $USER)
#   rvos-br0   — bridge with IP 10.0.2.2/24
#   dnsmasq    — DHCP server on the bridge (if installed)
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

# Start dnsmasq DHCP server on the bridge (if not already running)
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
no-resolv
no-hosts
EOF
        dnsmasq -C "$DNSMASQ_CONF" --pid-file="$DNSMASQ_PID"
        echo "Started dnsmasq (PID $(cat "$DNSMASQ_PID"), DHCP 10.0.2.10–10.0.2.200)"
    fi
else
    echo "WARNING: dnsmasq not installed — no DHCP server"
    echo "  Guest will fall back to static IP 10.0.2.15"
    echo "  Install: sudo apt install dnsmasq"
fi

echo "TAP=$TAP  BRIDGE=$BR  BRIDGE_IP=10.0.2.2/24  (owner=$OWNER)"
echo "Ready.  Run:  make run"
