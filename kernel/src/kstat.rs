//! Kernel statistics: always-on atomic counters and latency histograms.
//!
//! All counters use `AtomicU64` with `Relaxed` ordering (single `amoadd.d`
//! on RV64 — no fences, no locks). The counters are monotonic and never reset.

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::string::String;
use core::fmt::Write;

// ============================================================
// Counters
// ============================================================

macro_rules! define_counters {
    ($($name:ident),* $(,)?) => {
        $(pub static $name: AtomicU64 = AtomicU64::new(0);)*

        /// Snapshot all counters into a formatted string.
        pub fn format_counters() -> String {
            let mut out = String::new();
            $(
                let _ = writeln!(out, "  {:<24} {}", stringify!($name), $name.load(Ordering::Relaxed));
            )*
            out
        }
    };
}

define_counters! {
    // Scheduler
    SCHED_SWITCHES,
    SCHED_PREEMPTS,
    SCHED_YIELDS,
    // IPC
    IPC_SENDS,
    IPC_RECVS,
    IPC_SEND_BLOCKS,
    IPC_RECV_BLOCKS,
    // Channels
    CHANNELS_CREATED,
    CHANNELS_CLOSED,
    // Pages
    PAGES_ALLOCATED,
    PAGES_FREED,
    // Interrupts
    IRQ_TIMER,
    IRQ_UART,
    IRQ_VIRTIO_KBD,
    IRQ_VIRTIO_NET,
    IRQ_VIRTIO_GPU,
    IRQ_VIRTIO_BLK,
    IRQ_PLIC_OTHER,
}

/// Increment a counter by 1.
#[inline(always)]
pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

// ============================================================
// Log2 Histogram
// ============================================================

/// Number of buckets. Bucket i covers values in [2^i, 2^(i+1)).
/// Bucket 0 = [0, 2), bucket 1 = [2, 4), ..., bucket 31 = [2^31, 2^32).
const NUM_BUCKETS: usize = 32;

pub struct Log2Hist {
    buckets: [AtomicU64; NUM_BUCKETS],
}

impl Log2Hist {
    pub const fn new() -> Self {
        Log2Hist {
            buckets: [const { AtomicU64::new(0) }; NUM_BUCKETS],
        }
    }

    /// Record a value into the appropriate bucket.
    #[inline(always)]
    #[allow(dead_code)] // used in later commits (latency histograms)
    pub fn record(&self, value: u64) {
        let bucket = if value == 0 {
            0
        } else {
            (63 - value.leading_zeros()) as usize
        };
        let bucket = bucket.min(NUM_BUCKETS - 1);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// Format as a Brendan Gregg-style ASCII histogram.
    /// Values are shown in the unit provided (e.g., "us" for microseconds).
    pub fn format(&self, title: &str, unit: &str, ticks_per_unit: u64) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "  {}", title);

        // Find the maximum count for scaling the bar width
        let mut max_count: u64 = 0;
        let mut total: u64 = 0;
        for b in &self.buckets {
            let c = b.load(Ordering::Relaxed);
            if c > max_count {
                max_count = c;
            }
            total += c;
        }

        if total == 0 {
            let _ = writeln!(out, "  (no data)");
            return out;
        }

        const BAR_WIDTH: usize = 30;

        // Print header
        let _ = writeln!(out, "  {:>12} {:>12}  {:>8}  distribution", unit, "", "count");

        // Only print buckets that have data (or are between data buckets)
        let mut first_nonzero = NUM_BUCKETS;
        let mut last_nonzero = 0;
        for (i, b) in self.buckets.iter().enumerate() {
            if b.load(Ordering::Relaxed) > 0 {
                if i < first_nonzero {
                    first_nonzero = i;
                }
                last_nonzero = i;
            }
        }

        if first_nonzero > last_nonzero {
            let _ = writeln!(out, "  (no data)");
            return out;
        }

        for i in first_nonzero..=last_nonzero {
            let count = self.buckets[i].load(Ordering::Relaxed);
            let lo = (1u64 << i).checked_div(ticks_per_unit).unwrap_or(1u64 << i);
            let hi = (1u64 << (i + 1)).saturating_sub(1)
                .checked_div(ticks_per_unit)
                .unwrap_or((1u64 << (i + 1)).saturating_sub(1));
            let bar_len = if max_count > 0 {
                ((count as u128 * BAR_WIDTH as u128) / max_count as u128) as usize
            } else {
                0
            };
            let mut bar = [0u8; BAR_WIDTH];
            for b in bar.iter_mut().take(bar_len) {
                *b = b'#';
            }
            for b in bar.iter_mut().skip(bar_len) {
                *b = b' ';
            }
            let bar_str = core::str::from_utf8(&bar).unwrap_or("");
            let _ = writeln!(out, "  {:>12} -> {:<12} {:>8}  |{}|",
                lo, hi, count, bar_str);
        }
        let _ = writeln!(out, "  total: {}", total);
        out
    }
}

// Global histogram statics
pub static SCHED_LATENCY: Log2Hist = Log2Hist::new();
pub static IPC_LATENCY: Log2Hist = Log2Hist::new();
