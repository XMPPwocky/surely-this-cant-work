#!/bin/bash
# Set up TAP device + bridge for rvOS networking.
# Must be run as root (or via sudo).
#
# Creates:
#   rvos-tap0  — TAP device owned by $SUDO_USER (or $USER)
#   rvos-br0   — bridge with IP 10.0.2.2/24
#
# The guest hardcodes IP 10.0.2.15/24 with gateway 10.0.2.2.

set -e

TAP=rvos-tap0
BR=rvos-br0
OWNER=${SUDO_USER:-$USER}

# Tear down any stale state first
ip link set "$TAP" down 2>/dev/null || true
ip link set "$BR"  down 2>/dev/null || true
ip link del "$BR"  2>/dev/null || true
ip tuntap del dev "$TAP" mode tap 2>/dev/null || true

# Create TAP device owned by the calling user
ip tuntap add dev "$TAP" mode tap user "$OWNER"
ip link set "$TAP" up

# Create bridge and attach TAP
ip link add "$BR" type bridge
ip link set "$TAP" master "$BR"
ip link set "$BR" up

# Assign the gateway IP that the guest expects
ip addr add 10.0.2.2/24 dev "$BR"

echo "TAP=$TAP  BRIDGE=$BR  BRIDGE_IP=10.0.2.2/24  (owner=$OWNER)"
echo "Ready.  Run:  make run-tap"
