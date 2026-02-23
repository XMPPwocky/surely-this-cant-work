//! Boot channel protocol.
//!
//! The boot channel (handle 0) is the first IPC channel available to every user
//! process. It connects to the init server and provides service discovery and
//! process spawning. See docs/protocols/boot-channel.md for the full spec.
//!
//! Because the server (init) handles requests in a complex async polling loop,
//! this protocol uses `define_message!` only — not `define_protocol!`.

use rvos_wire::define_message;

define_message! {
    /// Requests on the boot channel (client → init).
    pub enum BootRequest<'a> => BootRequestMsg {
        /// Connect to a named service (e.g., "stdio", "sysinfo", "math", "fs").
        /// Response cap = client endpoint of the service channel.
        ConnectService(0) { name: &'a str },
        /// Spawn a new process from a filesystem path (e.g., "/bin/hello-std").
        /// `args` is a null-separated blob (e.g. b"arg1\0arg2\0arg3"), empty if none.
        /// `ns_overrides` is a packed blob for namespace overrides, empty if none.
        /// Response cap = process handle channel.
        Spawn(1) { path: &'a str, args: &'a [u8], ns_overrides: &'a [u8], suspended: bool },
        /// Fetch command-line arguments for this process.
        /// Response = Args with null-separated blob.
        GetArgs(2) {},
    }
}

define_message! {
    /// Responses on the boot channel (init → client).
    pub enum BootResponse<'a> => BootResponseMsg {
        /// Success. The message cap field carries the requested handle.
        Ok(0) {},
        /// Failure. `message` is a human-readable error string.
        Error(1) { message: &'a str },
        /// Command-line arguments (null-separated blob).
        Args(2) { args: &'a [u8] },
    }
}
