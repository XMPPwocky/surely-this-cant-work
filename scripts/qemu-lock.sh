#!/usr/bin/env bash
# Wrapper that runs QEMU as a background child with signal handling
# for clean shutdown on Ctrl-C / expect timeout.
#
# Usage: scripts/qemu-lock.sh qemu-system-riscv64 ...
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 COMMAND..." >&2
    exit 2
fi

# Run QEMU as a background child so we can clean up on signal/exit.
# Explicit 0<&0 keeps stdin connected to the terminal.  Without it,
# bash redirects a background job's stdin from /dev/null (POSIX rule
# for async commands when job control is off), which silently breaks
# QEMU's -serial mon:stdio input path.
"$@" 0<&0 &
QEMU_PID=$!

# Kill QEMU when this script exits for any reason.
# We must explicitly trap INT/TERM/HUP (not just EXIT) because bash only
# interrupts `wait` for signals with explicit traps.  An untrapped SIGTERM
# kills the script without running the EXIT handler.
cleanup() { kill $QEMU_PID 2>/dev/null; wait $QEMU_PID 2>/dev/null; }
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 129' HUP
trap 'cleanup'            EXIT

# Wait for QEMU to exit
wait $QEMU_PID 2>/dev/null || true
