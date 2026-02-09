//! Filesystem service protocol.
//!
//! Defines the control channel and per-file channel message types.
//! See docs/protocols/filesystem.md for the full protocol specification.

use rvos_wire::define_message;

// ── Error codes ──────────────────────────────────────────────────

define_message! {
    /// Filesystem error codes.
    pub enum FsError {
        NotFound(1) {},
        AlreadyExists(2) {},
        NotAFile(3) {},
        NotEmpty(4) {},
        InvalidPath(5) {},
        NoSpace(6) {},
        Io(7) {},
    }
}

// ── Open flags (bitfield — newtype with named constants) ─────────

define_message! {
    pub struct OpenFlags { bits: u8 }
}

impl OpenFlags {
    pub const OPEN: Self       = Self { bits: 0x00 };
    pub const CREATE: Self     = Self { bits: 0x01 };
    pub const TRUNCATE: Self   = Self { bits: 0x02 };
    pub const EXCL: Self       = Self { bits: 0x04 };
    pub const CREATE_NEW: Self = Self { bits: 0x05 }; // CREATE | EXCL
    pub const APPEND: Self     = Self { bits: 0x08 };

    /// Combine flags with bitwise OR.
    pub const fn or(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }
}

// ── Stat result kind ─────────────────────────────────────────────

define_message! {
    /// What kind of filesystem entry this is.
    pub enum FsEntryKind {
        File(0) {},
        Directory(1) {},
    }
}

// ── Control channel requests/responses ───────────────────────────

define_message! {
    /// Requests on the filesystem control channel.
    pub enum FsRequest<'a> {
        /// Open/create a file. Response cap = file channel endpoint.
        Open(0) { flags: OpenFlags, path: &'a str },
        /// Delete a file or empty directory.
        Delete(1) { path: &'a str },
        /// Get file metadata (size, kind).
        Stat(2) { path: &'a str },
        /// List directory entries (streaming response).
        Readdir(3) { path: &'a str },
    }
}

define_message! {
    /// Responses on the filesystem control channel.
    pub enum FsResponse {
        /// Success. For Open: msg.cap carries file channel.
        /// For Stat: includes metadata fields.
        Ok(0) { kind: FsEntryKind, size: u64 },
        /// Error with structured code.
        Error(1) { code: FsError },
    }
}

// ── Readdir streaming responses ──────────────────────────────────

define_message! {
    /// Individual messages in a readdir response stream.
    /// Sent on the control channel after a Readdir request.
    pub enum ReaddirResponse<'a> {
        /// A directory entry.
        Entry(0) { kind: FsEntryKind, size: u64, name: &'a str },
        /// Error (same codes as FsResponse::Error).
        Error(1) { code: FsError },
        /// End of listing sentinel.
        End(2) {},
    }
}

// ── File offset ─────────────────────────────────────────────────

define_message! {
    /// How to interpret the file position for a read/write.
    pub enum FileOffset {
        /// Use this explicit byte offset.
        Explicit(0) { offset: u64 },
        /// Use the server-tracked stream position (e.g. stdio).
        Stream(1) {},
    }
}

// ── Per-file channel requests/responses ──────────────────────────

define_message! {
    /// Requests on a per-file channel.
    pub enum FileRequest<'a> {
        /// Read up to `len` bytes starting at `offset`.
        Read(0) { offset: FileOffset, len: u32 },
        /// Write `data` starting at `offset`.
        Write(1) { offset: FileOffset, data: &'a [u8] },
        /// Terminal ioctl (cmd + arg).
        Ioctl(2) { cmd: u32, arg: u32 },
    }
}

define_message! {
    /// Responses on a per-file channel.
    pub enum FileResponse<'a> {
        /// Data chunk. Empty chunk = end-of-stream sentinel.
        Data(0) { chunk: &'a [u8] },
        /// Write succeeded.
        WriteOk(1) { written: u32 },
        /// Error with structured code.
        Error(2) { code: FsError },
        /// Ioctl succeeded.
        IoctlOk(3) { result: u32 },
    }
}

// ── Ioctl command constants ─────────────────────────────────────

/// Enable raw mode (arg ignored).
pub const TCRAW: u32 = 1;
/// Disable raw mode (arg ignored).
pub const TCCOOKED: u32 = 2;

use rvos_wire::define_protocol;

// FileOps must be defined before FsControl so that FileOpsClient
// is available for the [-> FileOpsClient] typed capability annotation.

define_protocol! {
    /// Per-file data channel protocol.
    pub protocol FileOps => FileOpsClient, FileOpsHandler, file_ops_dispatch {
        type Request<'a> = FileRequest;
        type Response<'a> = FileResponse;

        /// Read data from offset.
        rpc read as Read(offset: FileOffset, len: u32) -> FileResponse<'_>;
        /// Write data at offset.
        rpc write as Write(offset: FileOffset, data: &[u8]) -> FileResponse<'_>;
        /// Terminal ioctl.
        rpc ioctl as Ioctl(cmd: u32, arg: u32) -> FileResponse<'_>;
    }
}

define_protocol! {
    /// Filesystem control channel protocol.
    pub protocol FsControl => FsControlClient, FsControlHandler, fs_control_dispatch {
        type Request<'a> = FsRequest;
        type Response = FsResponse;

        /// Open/create a file. Returns (response, FileOpsClient).
        rpc open as Open(flags: OpenFlags, path: &str) -> FsResponse [-> FileOpsClient];
        /// Delete a file or empty directory.
        rpc delete as Delete(path: &str) -> FsResponse;
        /// Get file metadata.
        rpc stat as Stat(path: &str) -> FsResponse;
        /// List directory entries (streaming response).
        rpc readdir as Readdir(path: &str) -> FsResponse;
    }
}
