//! Process debugger protocol.
//!
//! Defines the control channel (attach handshake), per-process session
//! channel (debug commands), and event channel (async notifications).

use rvos_wire::define_message;
use rvos_wire::RawChannelCap;

// ── Error codes ──────────────────────────────────────────────────

define_message! {
    /// Debug error codes.
    pub enum DebugError {
        NotFound(0) {},
        AlreadyAttached(1) {},
        NotAUserProcess(2) {},
        NoResources(3) {},
    }
}

// ── Control channel (attach handshake) ──────────────────────────

define_message! {
    /// Attach request on the control channel.
    pub struct DebugAttachRequest { pid: u32 }
}

define_message! {
    /// Attach response on the control channel.
    /// On success, embeds a session channel and an event channel.
    pub owned enum DebugAttachResponse {
        /// Attach succeeded.
        Ok(0)    { session: RawChannelCap, events: RawChannelCap },
        /// Attach failed.
        Error(1) { code: DebugError },
    }
}

// ── Session channel (per-process debug commands) ────────────────

define_message! {
    /// Requests on the per-process session channel.
    pub enum SessionRequest<'a> => SessionRequestMsg {
        Suspend(0)         {},
        Resume(1)          {},
        ReadRegisters(2)   {},
        WriteRegister(3)   { reg: u8, value: u64 },
        ReadMemory(4)      { addr: u64, len: u32 },
        WriteMemory(5)     { addr: u64, data: &'a [u8] },
        SetBreakpoint(6)   { addr: u64 },
        ClearBreakpoint(7) { addr: u64 },
        Backtrace(8)       {},
    }
}

define_message! {
    /// Responses on the per-process session channel.
    pub enum SessionResponse<'a> => SessionResponseMsg {
        Ok(0)         {},
        Error(1)      { message: &'a str },
        /// Register dump: pc followed by 32 GPRs, packed as little-endian u64s (264 bytes).
        Registers(2)  { data: &'a [u8] },
        Memory(3)     { data: &'a [u8] },
        Backtrace(4)  { frames: &'a [u8] },  // packed [(ra: u64, fp: u64); N]
    }
}

use rvos_wire::define_protocol;

define_protocol! {
    /// Per-process debug session protocol.
    pub protocol DebugSession => DebugSessionClient, DebugSessionHandler,
                                 debug_session_dispatch, debug_session_handle {
        type Request<'a> = SessionRequest;
        type Response<'a> = SessionResponse;

        rpc suspend as Suspend() -> SessionResponse<'_>;
        rpc resume as Resume() -> SessionResponse<'_>;
        rpc read_registers as ReadRegisters() -> SessionResponse<'_>;
        rpc write_register as WriteRegister(reg: u8, value: u64) -> SessionResponse<'_>;
        rpc read_memory as ReadMemory(addr: u64, len: u32) -> SessionResponse<'_>;
        rpc write_memory as WriteMemory(addr: u64, data: &[u8]) -> SessionResponse<'_>;
        rpc set_breakpoint as SetBreakpoint(addr: u64) -> SessionResponse<'_>;
        rpc clear_breakpoint as ClearBreakpoint(addr: u64) -> SessionResponse<'_>;
        rpc backtrace as Backtrace() -> SessionResponse<'_>;
    }
}

// ── Event channel (async push from service to debugger) ─────────

define_message! {
    /// Async events pushed on the event channel.
    pub enum DebugEvent {
        /// Target hit a breakpoint at `addr`.
        BreakpointHit(0)  { addr: u64 },
        /// Target was force-suspended (in response to Suspend command).
        Suspended(1)      {},
        /// Target process exited.
        ProcessExited(2)  { exit_code: i32 },
    }
}
