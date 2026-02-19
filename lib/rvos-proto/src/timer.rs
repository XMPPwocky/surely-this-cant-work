//! Timer service protocol.
//!
//! The timer service provides timed wakeups via channel IPC. A client sends
//! `After { duration_us }` and receives `Expired` when the requested duration
//! has elapsed. Timer channels can be polled alongside other channels using
//! `sys_chan_poll_add` + `sys_block`, giving a natural reactor-style event loop.

use rvos_wire::define_message;
use rvos_wire::define_protocol;

define_message! {
    /// Timer service requests.
    pub enum TimerRequest {
        /// Reply after `duration_us` microseconds.
        After(0) { duration_us: u64 },
    }
}

define_message! {
    /// Timer service responses.
    pub enum TimerResponse {
        /// The requested duration has elapsed.
        Expired(0) {},
    }
}

define_protocol! {
    /// Timer service protocol.
    pub protocol Timer =>
        TimerClient, TimerHandler, timer_dispatch, timer_handle
    {
        type Request = TimerRequest;
        type Response = TimerResponse;

        /// Request a timed wakeup after the given duration.
        rpc after as After(duration_us: u64) -> TimerResponse;
    }
}
