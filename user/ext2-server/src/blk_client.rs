//! Block device client — connects to a blk_server and provides block I/O.

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::blk::{BlkRequest, BlkResponse};

/// Block device client connected to a blk_server instance.
pub struct BlkClient {
    handle: usize,
    shm_addr: usize,
    shm_cap: usize,
    pub capacity_sectors: u64,
    pub sector_size: u32,
    pub read_only: bool,
}

/// SHM region size: 32 pages = 128 KB.
const SHM_PAGES: usize = 32;
const SHM_SIZE: usize = SHM_PAGES * 4096;

/// Maximum sectors per single I/O: SHM_SIZE / 512.
pub const MAX_SECTORS_PER_IO: u32 = (SHM_SIZE / 512) as u32;

impl BlkClient {
    /// Connect to a named block device service (e.g., "blk0").
    pub fn connect(name: &str) -> Result<Self, &'static str> {
        let svc = rvos::connect_to_service(name)
            .map_err(|_| "connect to blk service failed")?;
        let handle = svc.into_raw_handle();

        // Send GetDeviceInfo
        let req = BlkRequest::GetDeviceInfo {};
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(&req, &mut msg.data).unwrap_or(0);
        raw::sys_chan_send_blocking(handle, &msg);

        // Receive DeviceInfo + SHM cap
        let mut resp_msg = Message::new();
        let ret = raw::sys_chan_recv_blocking(handle, &mut resp_msg);
        if ret != 0 {
            raw::sys_chan_close(handle);
            return Err("recv DeviceInfo failed");
        }

        let shm_cap = resp_msg.caps[0];
        if shm_cap == NO_CAP {
            raw::sys_chan_close(handle);
            return Err("no SHM cap in DeviceInfo");
        }

        let resp: BlkResponse = rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len])
            .map_err(|_| {
                raw::sys_chan_close(handle);
                raw::sys_chan_close(shm_cap);
                "decode DeviceInfo failed"
            })?;

        let (capacity_sectors, sector_size, read_only) = match resp {
            BlkResponse::DeviceInfo { capacity_sectors, sector_size, read_only } => {
                (capacity_sectors, sector_size, read_only != 0)
            }
            _ => {
                raw::sys_chan_close(handle);
                raw::sys_chan_close(shm_cap);
                return Err("unexpected response (not DeviceInfo)");
            }
        };

        // Map SHM
        let shm_addr = raw::sys_mmap(shm_cap, SHM_SIZE);
        if shm_addr == usize::MAX {
            raw::sys_chan_close(handle);
            raw::sys_chan_close(shm_cap);
            return Err("mmap SHM failed");
        }

        Ok(BlkClient {
            handle,
            shm_addr,
            shm_cap,
            capacity_sectors,
            sector_size,
            read_only,
        })
    }

    /// Send a request and receive a response.
    fn request(&self, req: &BlkRequest) -> Result<BlkResponse, &'static str> {
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(req, &mut msg.data).unwrap_or(0);
        raw::sys_chan_send_blocking(self.handle, &msg);

        let mut resp_msg = Message::new();
        let ret = raw::sys_chan_recv_blocking(self.handle, &mut resp_msg);
        if ret != 0 {
            return Err("recv blk response failed");
        }

        rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len])
            .map_err(|_| "decode blk response failed")
    }

    /// Read `count` sectors starting at `sector` into `buf`.
    /// `buf` must be at least `count * sector_size` bytes.
    pub fn read_sectors(&self, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        let byte_len = count as usize * self.sector_size as usize;
        if buf.len() < byte_len {
            return Err("buffer too small");
        }
        if count > MAX_SECTORS_PER_IO {
            return Err("too many sectors for single I/O");
        }

        let resp = self.request(&BlkRequest::Read { sector, count, shm_offset: 0 })?;
        match resp {
            BlkResponse::Ok {} => {
                // Copy from SHM to caller's buffer
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.shm_addr as *const u8,
                        buf.as_mut_ptr(),
                        byte_len,
                    );
                }
                Ok(())
            }
            BlkResponse::Error { code } => {
                Err(match code {
                    22 => "read: out of bounds",
                    5 => "read: I/O error",
                    _ => "read: unknown error",
                })
            }
            _ => Err("read: unexpected response"),
        }
    }

    /// Write `count` sectors starting at `sector` from `buf`.
    /// `buf` must be at least `count * sector_size` bytes.
    pub fn write_sectors(&self, sector: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
        let byte_len = count as usize * self.sector_size as usize;
        if buf.len() < byte_len {
            return Err("buffer too small");
        }
        if count > MAX_SECTORS_PER_IO {
            return Err("too many sectors for single I/O");
        }

        // Copy data to SHM
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                self.shm_addr as *mut u8,
                byte_len,
            );
        }

        let resp = self.request(&BlkRequest::Write { sector, count, shm_offset: 0 })?;
        match resp {
            BlkResponse::Ok {} => Ok(()),
            BlkResponse::Error { code } => {
                Err(match code {
                    30 => "write: read-only device",
                    22 => "write: out of bounds",
                    5 => "write: I/O error",
                    _ => "write: unknown error",
                })
            }
            _ => Err("write: unexpected response"),
        }
    }

    /// Read a single block (ext2 block = `block_size` bytes, typically 1024 or 4096).
    /// `block_size` must be a multiple of sector_size.
    pub fn read_block(&self, block_num: u64, block_size: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        let sectors_per_block = block_size / self.sector_size;
        let start_sector = block_num * sectors_per_block as u64;
        self.read_sectors(start_sector, sectors_per_block, buf)
    }

    /// Write a single block.
    pub fn write_block(&self, block_num: u64, block_size: u32, buf: &[u8]) -> Result<(), &'static str> {
        let sectors_per_block = block_size / self.sector_size;
        let start_sector = block_num * sectors_per_block as u64;
        self.write_sectors(start_sector, sectors_per_block, buf)
    }

    /// Flush any cached writes to stable storage.
    #[allow(dead_code)] // Used in Step 13 (RW operations)
    pub fn flush(&self) -> Result<(), &'static str> {
        let resp = self.request(&BlkRequest::Flush {})?;
        match resp {
            BlkResponse::Ok {} => Ok(()),
            BlkResponse::Error { .. } => Err("flush failed"),
            _ => Err("flush: unexpected response"),
        }
    }
}

impl Drop for BlkClient {
    fn drop(&mut self) {
        raw::sys_munmap(self.shm_addr, SHM_SIZE);
        raw::sys_chan_close(self.shm_cap);
        raw::sys_chan_close(self.handle);
    }
}
