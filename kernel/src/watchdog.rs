//! System watchdog — detects kernel task and critical process hangs.
//!
//! Three-tier watchdog:
//! - Tier 1: Timer interrupt liveness (implicit — if timer_tick stops, only
//!   the external expect script timeout catches it).
//! - Tier 2: Kernel task heartbeats — critical kernel tasks call `heartbeat()`
//!   each iteration of their main loop. Checked from `timer_tick()`.
//! - Tier 3: User process heartbeats — critical user processes call
//!   `sys_heartbeat()` syscall. Checked alongside tier 2.
//!
//! Configuration via FDT bootargs:
//! - `no-watchdog` — disable all tiers
//! - `watchdog=N` — set timeout to N seconds (default: 10)

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// ── Slot constants ───────────────────────────────────────────────────

pub const SLOT_INIT: usize = 0;
pub const SLOT_CONSOLE: usize = 1;
pub const SLOT_TIMER: usize = 2;
pub const SLOT_SYSINFO: usize = 3;

const MAX_WATCHED: usize = 8;
const DEFAULT_TIMEOUT_SECS: u64 = 10;

// ── Static state ─────────────────────────────────────────────────────

struct HeartbeatSlot {
    last_beat: AtomicU64,
    timeout_ticks: AtomicU64, // 0 = slot inactive
}

impl HeartbeatSlot {
    const fn new() -> Self {
        HeartbeatSlot {
            last_beat: AtomicU64::new(0),
            timeout_ticks: AtomicU64::new(0),
        }
    }
}

static SLOTS: [HeartbeatSlot; MAX_WATCHED] = [const { HeartbeatSlot::new() }; MAX_WATCHED];

/// Slot names for diagnostics (indexed by slot constant).
static SLOT_NAMES: [&str; MAX_WATCHED] = [
    "init", "console", "timer", "sysinfo",
    "(unused4)", "(unused5)", "(unused6)", "(unused7)",
];

static ENABLED: AtomicBool = AtomicBool::new(false);
static TIMEOUT_TICKS: AtomicU64 = AtomicU64::new(0);

// ── Public API ───────────────────────────────────────────────────────

/// Initialize the watchdog from bootargs. Call after `platform::init_from_fdt()`.
pub fn init() {
    let args = crate::platform::bootargs();
    let config = parse_bootargs(args);

    if !config.enabled {
        crate::println!("[watchdog] Disabled by bootargs");
        return;
    }

    let freq = crate::platform::timebase_frequency();
    let ticks = config.timeout_secs * freq;
    TIMEOUT_TICKS.store(ticks, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);

    crate::println!("[watchdog] Enabled, timeout={}s ({} ticks)", config.timeout_secs, ticks);
}

/// Register a kernel task heartbeat slot. Must be called before `pet_all()`.
pub fn register(slot: usize, _name: &'static str) {
    if !ENABLED.load(Ordering::Relaxed) || slot >= MAX_WATCHED {
        return;
    }
    let timeout = TIMEOUT_TICKS.load(Ordering::Relaxed);
    SLOTS[slot].timeout_ticks.store(timeout, Ordering::Relaxed);
}

/// Pet the watchdog for a kernel task slot (called in main loop).
#[inline]
pub fn heartbeat(slot: usize) {
    if slot < MAX_WATCHED {
        let now = crate::task::process::rdtime();
        SLOTS[slot].last_beat.store(now, Ordering::Relaxed);
    }
}

/// Reset all active slots to "now" — call right before enabling the timer
/// so boot time doesn't count against the timeout.
pub fn pet_all() {
    let now = crate::task::process::rdtime();
    for slot in &SLOTS {
        if slot.timeout_ticks.load(Ordering::Relaxed) != 0 {
            slot.last_beat.store(now, Ordering::Relaxed);
        }
    }
}

/// Return the recommended interval (in ticks) between heartbeats.
/// Services use this as their maximum blocking duration: block with a deadline
/// of `rdtime() + pet_interval()`, wake on expiry, heartbeat, re-block.
/// Returns 0 when the watchdog is disabled — callers treat 0 as "block forever."
pub fn pet_interval() -> u64 {
    TIMEOUT_TICKS.load(Ordering::Relaxed) / 2
}

/// Check all heartbeat slots. Called from `timer_tick()`.
/// If any slot has timed out, fires the watchdog (prints diagnostics + shutdown).
pub fn check(now: u64) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }

    // Tier 2: kernel task heartbeats
    for (i, slot) in SLOTS.iter().enumerate() {
        let timeout = slot.timeout_ticks.load(Ordering::Relaxed);
        if timeout == 0 {
            continue;
        }
        let last = slot.last_beat.load(Ordering::Relaxed);
        if last != 0 && now.wrapping_sub(last) > timeout {
            fire(i, now, last);
        }
    }

    // Tier 3: critical user processes
    let timeout = TIMEOUT_TICKS.load(Ordering::Relaxed);
    if let Some((pid, name_buf, last_hb)) = crate::task::check_critical_heartbeats(now, timeout) {
        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
        let name = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("?");
        fire_user(pid, name, now, last_hb);
    }
}

/// Format watchdog status for the shell `watchdog` command.
pub fn status() -> alloc::string::String {
    use alloc::string::String;
    use core::fmt::Write;

    let mut out = String::new();
    let enabled = ENABLED.load(Ordering::Relaxed);
    let timeout = TIMEOUT_TICKS.load(Ordering::Relaxed);
    let freq = crate::platform::timebase_frequency();
    let timeout_secs = timeout.checked_div(freq).unwrap_or(0);

    let _ = writeln!(out, "Watchdog: {}", if enabled { "enabled" } else { "disabled" });
    if !enabled {
        return out;
    }
    let _ = writeln!(out, "  Timeout: {}s ({} ticks)", timeout_secs, timeout);

    let now = crate::task::process::rdtime();
    let _ = writeln!(out, "  Kernel task heartbeats:");
    for (i, slot) in SLOTS.iter().enumerate() {
        let t = slot.timeout_ticks.load(Ordering::Relaxed);
        if t == 0 {
            continue;
        }
        let last = slot.last_beat.load(Ordering::Relaxed);
        let ago_ms = if last > 0 && freq > 0 {
            now.saturating_sub(last) / (freq / 1000)
        } else {
            0
        };
        let _ = writeln!(out, "    {:<12} last heartbeat {}ms ago", SLOT_NAMES[i], ago_ms);
    }

    // Tier 3: critical user processes
    let _ = writeln!(out, "  Critical user processes:");
    match crate::task::watchdog_process_status() {
        Some(s) if !s.is_empty() => {
            let _ = write!(out, "{}", s);
        }
        _ => {
            let _ = writeln!(out, "    (none or scheduler locked)");
        }
    }

    out
}

// ── Internal ─────────────────────────────────────────────────────────

/// Watchdog fired for a kernel task slot — print diagnostics and shut down.
fn fire(slot: usize, now: u64, last_beat: u64) -> ! {
    // Disable further checks
    ENABLED.store(false, Ordering::Relaxed);

    let freq = crate::platform::timebase_frequency();
    let elapsed_ms = if freq > 0 {
        now.saturating_sub(last_beat) / (freq / 1000)
    } else {
        0
    };

    crate::println!();
    crate::println!("!!! WATCHDOG TIMEOUT !!!");
    crate::println!("  Kernel task '{}' (slot {}) has not heartbeated in {}ms",
        SLOT_NAMES[slot], slot, elapsed_ms);
    print_diagnostics();
    crate::arch::sbi::sbi_shutdown();
}

/// Watchdog fired for a critical user process.
fn fire_user(pid: usize, name: &str, now: u64, last_beat: u64) -> ! {
    ENABLED.store(false, Ordering::Relaxed);

    let freq = crate::platform::timebase_frequency();
    let elapsed_ms = if freq > 0 {
        now.saturating_sub(last_beat) / (freq / 1000)
    } else {
        0
    };

    crate::println!();
    crate::println!("!!! WATCHDOG TIMEOUT !!!");
    crate::println!("  User process '{}' (PID {}) has not heartbeated in {}ms",
        name, pid, elapsed_ms);
    print_diagnostics();
    crate::arch::sbi::sbi_shutdown();
}

/// Print diagnostic info: kstat counters + process list (best-effort).
fn print_diagnostics() {
    // kstat counters are lock-free atomics, always safe
    crate::println!("--- kstat counters ---");
    let counters = crate::kstat::format_counters();
    for line in counters.lines() {
        crate::println!("{}", line);
    }

    // Process list — try_lock to avoid deadlock
    crate::println!("--- process list ---");
    match crate::task::try_process_list() {
        Some(list) => {
            for line in list.lines() {
                crate::println!("{}", line);
            }
        }
        None => {
            crate::println!("  (scheduler locked, cannot dump process list)");
        }
    }
}

// ── Bootargs parser ──────────────────────────────────────────────────

struct WatchdogConfig {
    enabled: bool,
    timeout_secs: u64,
}

fn parse_bootargs(args: &[u8]) -> WatchdogConfig {
    let mut config = WatchdogConfig {
        enabled: true,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    };

    if args.is_empty() {
        return config;
    }

    // Split on whitespace and scan for watchdog tokens
    let mut i = 0;
    while i < args.len() {
        // Skip whitespace
        while i < args.len() && (args[i] == b' ' || args[i] == b'\t') {
            i += 1;
        }
        if i >= args.len() {
            break;
        }

        // Find end of token
        let start = i;
        while i < args.len() && args[i] != b' ' && args[i] != b'\t' {
            i += 1;
        }
        let token = &args[start..i];

        if token == b"no-watchdog" {
            config.enabled = false;
        } else if token.starts_with(b"watchdog=") {
            // Parse the number after '='
            let num_start = b"watchdog=".len();
            if num_start < token.len() {
                let mut val: u64 = 0;
                let mut valid = true;
                for &b in &token[num_start..] {
                    if b.is_ascii_digit() {
                        val = val.saturating_mul(10).saturating_add((b - b'0') as u64);
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && val > 0 {
                    config.timeout_secs = val;
                }
            }
        }
    }

    config
}
