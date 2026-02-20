//! Block device protocol between kernel blk_server and userspace clients.
//!
//! The client connects to a named blk service (e.g., "blk0") via the boot
//! channel. The server sends a DeviceInfo response with an SHM capability
//! for bulk data transfer. Subsequent Read/Write requests reference offsets
//! within that SHM region.

use rvos_wire::define_message;

define_message! {
    /// Requests from client to blk_server.
    pub enum BlkRequest {
        /// Request device info (capacity, sector size, RO flag) and SHM handle.
        GetDeviceInfo(0) {},
        /// Read `count` sectors starting at `sector` into SHM at `shm_offset`.
        Read(1) { sector: u64, count: u32, shm_offset: u32 },
        /// Write `count` sectors starting at `sector` from SHM at `shm_offset`.
        Write(2) { sector: u64, count: u32, shm_offset: u32 },
        /// Flush any cached writes to stable storage.
        Flush(3) {},
    }
}

define_message! {
    /// Responses from blk_server to client.
    pub owned enum BlkResponse {
        /// Device info. SHM handle sent as cap in message sideband (cap index 0).
        DeviceInfo(0) { capacity_sectors: u64, sector_size: u32, read_only: u8 },
        /// Operation completed successfully.
        Ok(1) {},
        /// Operation failed with error code.
        Error(2) { code: u32 },
    }
}
