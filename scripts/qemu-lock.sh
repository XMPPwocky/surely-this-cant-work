#!/usr/bin/env bash
# Wrapper that ensures only one QEMU instance runs at a time for this project.
# Uses flock(1) on .qemu.lock in the project root.
#
# Usage: scripts/qemu-lock.sh --info "make run" -- qemu-system-riscv64 ...
set -euo pipefail

# Lockfile lives in the project root (same directory as Makefile)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCKFILE="$PROJECT_ROOT/.qemu.lock"

# Parse arguments
INFO="unknown"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --info) INFO="$2"; shift 2;;
        --) shift; break;;
        *) break;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 [--info TEXT] -- COMMAND..." >&2
    exit 2
fi

# Save existing lockfile contents for error reporting
HOLDER_INFO=$(cat "$LOCKFILE" 2>/dev/null || true)

# Open lockfile on fd 9 (append mode — avoids truncating holder's info)
exec 9>>"$LOCKFILE"

# Try non-blocking exclusive lock
if ! flock --nonblock 9; then
    # Re-read in case it changed between our read and the flock attempt
    HOLDER_INFO=$(cat "$LOCKFILE" 2>/dev/null || true)
    cat >&2 <<EOF
============================================================
ERROR: QEMU is already running for this project.
Another QEMU instance holds the lock — you cannot start a
second one. This may be from another agent or a manual session.

${HOLDER_INFO:+Lock holder: $HOLDER_INFO
}Lockfile:    $LOCKFILE

Wait for the other instance to finish, or kill it if stale.
Do NOT use 'pkill qemu' — it may kill the wrong instance.
============================================================
EOF
    exit 1
fi

# Lock acquired — write our info (truncate via path, not fd)
echo "pid=$$ target=\"$INFO\" started=\"$(date '+%H:%M:%S')\" user=${USER:-unknown}" > "$LOCKFILE"

# Run QEMU — lock held via fd 9 until process exits
exec "$@"
