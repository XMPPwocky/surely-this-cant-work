#!/bin/bash
# Forward a host port to an rvOS guest port via socat.
#
# Usage: scripts/port-forward.sh <host-port> <rvos-ip> <rvos-port>
#   e.g.: scripts/port-forward.sh 8080 10.0.2.10 80
#
# Writes PID to /run/rvos-forward-<host-port>.pid.
# Kill the socat process (or use the PID file) to stop forwarding.
#
# To expose from outside the incus container, add a proxy device on the host:
#   incus config device add <container> http proxy \
#     listen=tcp:0.0.0.0:8080 connect=tcp:127.0.0.1:8080

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <host-port> <rvos-ip> <rvos-port>"
    echo "  e.g.: $0 8080 10.0.2.10 80"
    exit 1
fi

HOST_PORT="$1"
RVOS_IP="$2"
RVOS_PORT="$3"
PID_FILE="/run/rvos-forward-${HOST_PORT}.pid"

if ! command -v socat &>/dev/null; then
    echo "Error: socat not installed. Install with: sudo apt install socat"
    exit 1
fi

# Check if already running
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Port forward already running on host port $HOST_PORT (PID $(cat "$PID_FILE"))"
    exit 0
fi

socat TCP-LISTEN:"$HOST_PORT",fork,reuseaddr TCP:"$RVOS_IP":"$RVOS_PORT" &
SOCAT_PID=$!
echo "$SOCAT_PID" > "$PID_FILE"

echo "Forwarding host:$HOST_PORT → $RVOS_IP:$RVOS_PORT (PID $SOCAT_PID)"
echo "Stop with: kill $SOCAT_PID"
