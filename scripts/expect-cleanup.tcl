# Shared cleanup for expect scripts.
# Source this after `spawn` to register signal handlers that kill the
# spawned process group on exit.  This prevents QEMU from orphaning
# when make test / make bench is interrupted (Ctrl-C, SIGTERM, timeout).
#
# Why: expect's `spawn` creates a new session on a PTY.  GNU Make (in
# the chain: expect → make → qemu-lock.sh → QEMU) may isolate recipe
# processes in separate process groups.  When expect exits and closes
# the PTY master, SIGHUP only reaches the session leader (make), not
# the recipe's process group.  This cleanup explicitly kills the entire
# spawned process group on any exit path.
#
# Usage (after spawn, before any expect):
#   spawn make run-quick
#   source [file dirname [info script]]/expect-cleanup.tcl

proc kill_spawned_pgroup {} {
    catch {
        set pid [exp_pid]
        if {$pid > 0} {
            # Kill the entire process group rooted at the spawned process.
            # The spawned make is the session leader, so its PGID = its PID.
            # All descendants (qemu-lock.sh, QEMU) share this PGID.
            catch {exec kill -- -$pid}
        }
    }
    catch {close}
    catch {wait}
}

# Clean up on signals (Ctrl-C, kill, PTY hangup)
trap {kill_spawned_pgroup; exit 1} {SIGINT SIGTERM SIGHUP}

# Wrap `exit` so ALL exit paths (including timeout handlers) clean up.
# Guard against double-sourcing.
if {![llength [info procs _original_exit]]} {
    rename exit _original_exit
    proc exit {args} {
        kill_spawned_pgroup
        if {[llength $args] == 0} {
            _original_exit 0
        } else {
            _original_exit [lindex $args 0]
        }
    }
}
