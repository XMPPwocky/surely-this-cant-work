//! Sysinfo service protocol.
//!
//! The sysinfo service accepts a single command per connection and responds
//! with a chunked text stream (multiple messages terminated by a zero-length
//! sentinel). See docs/protocols/sysinfo.md for the full specification.
//!
//! Because the response is a multi-message stream, this protocol does NOT use
//! `define_protocol!` (which assumes single request/response). Instead, only
//! the command enum is defined here; streaming is handled by the transport layer.

use rvos_wire::define_message;

define_message! {
    /// Commands accepted by the sysinfo service.
    pub enum SysinfoCommand {
        /// Process list (PID, state, CPU, memory, name).
        Ps(0) {},
        /// Kernel heap stats and per-process memory.
        Memstat(1) {},
        /// Read the kernel trace ring buffer.
        Trace(2) {},
        /// Clear the kernel trace ring buffer.
        TraceClear(3) {},
        /// Global kernel counters (scheduler, IPC, pages, IRQs).
        Kstat(4) {},
        /// Per-channel statistics table.
        Channels(5) {},
        /// Scheduler latency histogram.
        SchedLatency(6) {},
        /// IPC delivery latency histogram.
        IpcLatency(7) {},
        /// Watchdog status (enabled, timeout, per-slot heartbeats).
        Watchdog(8) {},
    }
}
