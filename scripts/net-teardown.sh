#!/bin/bash
# Tear down TAP device + bridge created by net-setup.sh.
# Must be run as root (or via sudo).

set -e

TAP=rvos-tap0
BR=rvos-br0

ip link set "$TAP" down 2>/dev/null || true
ip link set "$BR"  down 2>/dev/null || true
ip link del "$BR"  2>/dev/null || true
ip tuntap del dev "$TAP" mode tap 2>/dev/null || true

echo "Cleaned up $TAP and $BR."
