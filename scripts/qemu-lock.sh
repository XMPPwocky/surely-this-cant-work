#!/usr/bin/env bash
# Wrapper that ensures only one QEMU instance runs at a time for this project.
# Uses flock(1) on .qemu.lock in the project root.
#
# Usage: scripts/qemu-lock.sh --info "make run" -- qemu-system-riscv64 ...
set -euo pipefail

# Lockfile must be shared across all worktrees so parallel agents don't
# collide on host-side resources (TAP device, VNC port, named pipes).
# Use `git rev-parse --git-common-dir` to find the main repo's .git/,
# which is the same for every worktree.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GIT_COMMON="$(git -C "$PROJECT_ROOT" rev-parse --git-common-dir 2>/dev/null || echo "$PROJECT_ROOT/.git")"
LOCKFILE="$GIT_COMMON/.qemu.lock"

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

try_lock() {
    # Open lockfile on fd 9 (append mode — avoids truncating holder's info)
    exec 9>>"$LOCKFILE"
    flock --nonblock 9
}

if ! try_lock; then
    # Lock held — check if the holder is still alive
    HOLDER_PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' "$LOCKFILE" 2>/dev/null || true)
    if [[ -n "$HOLDER_PID" ]] && ! kill -0 "$HOLDER_PID" 2>/dev/null; then
        # Holder is dead; remove stale lockfile and retry once
        rm -f "$LOCKFILE"
        exec 9>&-  # close old fd so we get the new inode
        if try_lock; then
            LOCK_OK=1
        fi
    fi

    if [[ "${LOCK_OK:-}" != 1 ]]; then
        HOLDER_INFO=$(cat "$LOCKFILE" 2>/dev/null || true)
        cat >&2 <<EOF
============================================================
ERROR: QEMU is already running for this project.
Another QEMU instance holds the lock — you cannot start a
second one. This may be from another agent or a manual session.

${HOLDER_INFO:+Lock holder: $HOLDER_INFO
}Lockfile:    $LOCKFILE

You must wait for it to finish. Do NOT kill it — it may
belong to another agent or to the user.
============================================================
EOF
        exit 1
    fi
fi

# Lock acquired — write our info (truncate via path, not fd)
echo "pid=$$ target=\"$INFO\" started=\"$(date '+%H:%M:%S')\" user=${USER:-unknown}" > "$LOCKFILE"

# Run QEMU as a background child so we can clean up on signal/exit.
# Previously this used `exec "$@"`, but that replaces the script with QEMU,
# leaving no parent to handle cleanup when the process tree is torn down
# (e.g., Ctrl-C on `make test` where QEMU is on a separate PTY via expect).
"$@" &
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

# Wait for QEMU; lock (fd 9) is released when this script exits
wait $QEMU_PID 2>/dev/null || true
