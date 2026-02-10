//! Math service protocol.
//!
//! The math service accepts one request per client channel and returns a response.

use rvos_wire::define_message;

define_message! {
    /// Math operation request.
    pub enum MathRequest {
        /// Add two numbers.
        Add(0) { a: u32, b: u32 },
        /// Multiply two numbers.
        Mul(1) { a: u32, b: u32 },
        /// Subtract b from a.
        Sub(2) { a: u32, b: u32 },
    }
}

define_message! {
    /// Math operation response.
    pub struct MathResponse { answer: u32 }
}

use rvos_wire::define_protocol;

define_protocol! {
    /// Math service protocol.
    pub protocol Math => MathClient, MathHandler, math_dispatch, math_handle {
        type Request = MathRequest;
        type Response = MathResponse;

        /// Add two numbers.
        rpc add as Add(a: u32, b: u32) -> MathResponse;
        /// Multiply two numbers.
        rpc mul as Mul(a: u32, b: u32) -> MathResponse;
        /// Subtract b from a.
        rpc sub as Sub(a: u32, b: u32) -> MathResponse;
    }
}
