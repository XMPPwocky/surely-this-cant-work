#!/bin/bash
# Set up TAP device + bridge for rvOS networking.
# Must be run as root (or via sudo).
#
# Creates (if not already present):
#   rvos-tap0  — TAP device owned by $SUDO_USER (or $USER)
#   rvos-br0   — bridge with IP 10.0.2.2/24
#
# The guest hardcodes IP 10.0.2.15/24 with gateway 10.0.2.2.
#
# Idempotent — safe to run multiple times.

set -e

TAP=rvos-tap0
BR=rvos-br0
OWNER=${SUDO_USER:-$USER}

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

echo "TAP=$TAP  BRIDGE=$BR  BRIDGE_IP=10.0.2.2/24  (owner=$OWNER)"
echo "Ready.  Run:  make run"
