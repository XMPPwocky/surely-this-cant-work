//! ext2 on-disk format parsing and read-only operations.
//!
//! Supports: superblock, block group descriptors, inodes, directory traversal,
//! file data reads via direct + single/double indirect blocks.

use crate::blk_client::BlkClient;
use crate::block_cache::BlockCache;

/// ext2 magic number.
const EXT2_MAGIC: u16 = 0xEF53;

/// Root directory inode number.
pub const ROOT_INO: u32 = 2;

// Inode mode type bits (bits 12-15 of i_mode).
const S_IFDIR: u16 = 0x4000;
#[allow(dead_code)]
const S_IFREG: u16 = 0x8000;
const S_IFMT: u16 = 0xF000;

/// Parsed ext2 superblock.
#[allow(dead_code)]
pub struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u32,
    pub first_data_block: u32,
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub first_ino: u32,
}

/// Parsed block group descriptor.
struct BlockGroupDesc {
    inode_table: u32,
}

/// Parsed inode.
pub struct Inode {
    pub mode: u16,
    pub size: u64,
    pub blocks: [u32; 15],
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    #[allow(dead_code)]
    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// Read and validate the ext2 superblock from the block device.
pub fn read_superblock(blk: &BlkClient) -> Result<Superblock, &'static str> {
    // Superblock is at byte offset 1024, size 1024.
    // That's sectors 2-3 (with 512-byte sectors).
    let mut buf = [0u8; 1024];
    blk.read_sectors(2, 2, &mut buf)?;

    let magic = u16_le(&buf, 56);
    if magic != EXT2_MAGIC {
        return Err("not an ext2 filesystem (bad magic)");
    }

    let log_block_size = u32_le(&buf, 24);
    let block_size = 1024u32 << log_block_size;

    let rev_level = u32_le(&buf, 76);
    let inode_size = if rev_level >= 1 {
        u16_le(&buf, 88)
    } else {
        128
    };
    let first_ino = if rev_level >= 1 {
        u32_le(&buf, 84)
    } else {
        11
    };

    Ok(Superblock {
        inodes_count: u32_le(&buf, 0),
        blocks_count: u32_le(&buf, 4),
        first_data_block: u32_le(&buf, 20),
        block_size,
        blocks_per_group: u32_le(&buf, 32),
        inodes_per_group: u32_le(&buf, 40),
        inode_size,
        first_ino,
    })
}

/// Read a block group descriptor.
fn read_bgd(sb: &Superblock, group: u32, cache: &mut BlockCache, blk: &BlkClient) -> Result<BlockGroupDesc, &'static str> {
    // BGD table starts at the block after the superblock.
    // For 1024-byte blocks: superblock is in block 1, BGD table starts at block 2.
    // For larger blocks: superblock is in block 0 (bytes 1024-2047), BGD table starts at block 1.
    let bgd_start_block = if sb.block_size == 1024 { 2 } else { 1 };

    // Each BGD entry is 32 bytes.
    let bgd_offset = group as usize * 32;
    let bgd_block = bgd_start_block + (bgd_offset / sb.block_size as usize) as u64;
    let offset_in_block = bgd_offset % sb.block_size as usize;

    let data = cache.read(bgd_block, blk)?;
    let inode_table = u32_le(data, offset_in_block + 8);

    Ok(BlockGroupDesc { inode_table })
}

/// Read an inode by inode number (1-based).
pub fn read_inode(sb: &Superblock, ino: u32, cache: &mut BlockCache, blk: &BlkClient) -> Result<Inode, &'static str> {
    if ino == 0 || ino > sb.inodes_count {
        return Err("invalid inode number");
    }

    let group = (ino - 1) / sb.inodes_per_group;
    let index_in_group = (ino - 1) % sb.inodes_per_group;

    let bgd = read_bgd(sb, group, cache, blk)?;

    let inodes_per_block = sb.block_size / sb.inode_size as u32;
    let inode_table_block_offset = index_in_group / inodes_per_block;
    let offset_in_block = (index_in_group % inodes_per_block) as usize * sb.inode_size as usize;

    let block_num = bgd.inode_table as u64 + inode_table_block_offset as u64;
    let data = cache.read(block_num, blk)?;

    let off = offset_in_block;
    let mode = u16_le(data, off);
    let size_lo = u32_le(data, off + 4) as u64;
    let size_hi = u32_le(data, off + 108) as u64;
    let size = size_lo | (size_hi << 32);

    let mut blocks = [0u32; 15];
    for (j, block) in blocks.iter_mut().enumerate() {
        *block = u32_le(data, off + 40 + j * 4);
    }

    Ok(Inode { mode, size, blocks })
}

/// Resolve a file block index to a disk block number.
/// Handles direct, single indirect, and double indirect blocks.
pub fn resolve_block(sb: &Superblock, inode: &Inode, file_block: u32, cache: &mut BlockCache, blk: &BlkClient) -> Result<u32, &'static str> {
    let ptrs_per_block = sb.block_size / 4;

    if file_block < 12 {
        // Direct block
        return Ok(inode.blocks[file_block as usize]);
    }

    let file_block = file_block - 12;
    if file_block < ptrs_per_block {
        // Single indirect
        let indirect_block = inode.blocks[12];
        if indirect_block == 0 { return Ok(0); }
        let data = cache.read(indirect_block as u64, blk)?;
        return Ok(u32_le(data, file_block as usize * 4));
    }

    let file_block = file_block - ptrs_per_block;
    if file_block < ptrs_per_block * ptrs_per_block {
        // Double indirect
        let dind_block = inode.blocks[13];
        if dind_block == 0 { return Ok(0); }
        let first_idx = file_block / ptrs_per_block;
        let second_idx = file_block % ptrs_per_block;

        let data = cache.read(dind_block as u64, blk)?;
        let ind_block = u32_le(data, first_idx as usize * 4);
        if ind_block == 0 { return Ok(0); }

        let data = cache.read(ind_block as u64, blk)?;
        return Ok(u32_le(data, second_idx as usize * 4));
    }

    // Triple indirect — not supported (would handle files >64MB at 4K blocks)
    Err("triple indirect blocks not supported")
}

/// Read file data from an inode at a given byte offset.
/// Returns the number of bytes read (may be less than buf.len() at EOF).
pub fn read_data(
    sb: &Superblock,
    inode: &Inode,
    offset: u64,
    buf: &mut [u8],
    cache: &mut BlockCache,
    blk: &BlkClient,
) -> Result<usize, &'static str> {
    if offset >= inode.size {
        return Ok(0);
    }

    let available = (inode.size - offset) as usize;
    let to_read = buf.len().min(available);
    let mut read = 0usize;

    while read < to_read {
        let pos = offset as usize + read;
        let file_block = (pos / sb.block_size as usize) as u32;
        let offset_in_block = pos % sb.block_size as usize;

        let disk_block = resolve_block(sb, inode, file_block, cache, blk)?;
        if disk_block == 0 {
            // Sparse file — fill with zeros
            let chunk = (sb.block_size as usize - offset_in_block).min(to_read - read);
            buf[read..read + chunk].fill(0);
            read += chunk;
            continue;
        }

        let block_data = cache.read(disk_block as u64, blk)?;
        let chunk = (sb.block_size as usize - offset_in_block).min(to_read - read);
        buf[read..read + chunk].copy_from_slice(&block_data[offset_in_block..offset_in_block + chunk]);
        read += chunk;
    }

    Ok(read)
}

/// Look up a name in a directory inode. Returns the inode number if found.
pub fn dir_lookup(
    sb: &Superblock,
    dir_inode: &Inode,
    name: &[u8],
    cache: &mut BlockCache,
    blk: &BlkClient,
) -> Result<Option<u32>, &'static str> {
    if !dir_inode.is_dir() {
        return Err("not a directory");
    }

    let dir_size = dir_inode.size as usize;
    let mut pos = 0usize;

    while pos < dir_size {
        let file_block = (pos / sb.block_size as usize) as u32;
        let offset_in_block = pos % sb.block_size as usize;

        let disk_block = resolve_block(sb, dir_inode, file_block, cache, blk)?;
        if disk_block == 0 {
            break;
        }

        let block_data = cache.read(disk_block as u64, blk)?;
        let mut off = offset_in_block;

        while off + 8 <= sb.block_size as usize && pos < dir_size {
            let d_inode = u32_le(block_data, off);
            let rec_len = u16_le(block_data, off + 4) as usize;
            let name_len = block_data[off + 6] as usize;

            if rec_len == 0 {
                break; // Corrupted — avoid infinite loop
            }

            if d_inode != 0 && name_len == name.len()
                && block_data[off + 8..off + 8 + name_len] == *name
            {
                return Ok(Some(d_inode));
            }

            off += rec_len;
            pos += rec_len;
        }

        // If we consumed the block partially, advance to next block boundary
        if off <= offset_in_block {
            break; // No progress — avoid infinite loop
        }
        if !pos.is_multiple_of(sb.block_size as usize) {
            let remaining = sb.block_size as usize - (pos % sb.block_size as usize);
            pos += remaining;
        }
    }

    Ok(None)
}

/// Resolve a path (e.g., "/bin/hello") to an inode number.
/// The path must start with "/" for absolute paths, or be empty for root.
pub fn resolve_path(
    sb: &Superblock,
    path: &[u8],
    cache: &mut BlockCache,
    blk: &BlkClient,
) -> Result<u32, &'static str> {
    // Handle root
    if path.is_empty() || path == b"/" {
        return Ok(ROOT_INO);
    }

    // Strip leading slash
    let path = if path[0] == b'/' { &path[1..] } else { path };
    // Strip trailing slash
    let path = if !path.is_empty() && path[path.len() - 1] == b'/' {
        &path[..path.len() - 1]
    } else {
        path
    };

    if path.is_empty() {
        return Ok(ROOT_INO);
    }

    let mut current_ino = ROOT_INO;

    for component in path.split(|&b| b == b'/') {
        if component.is_empty() {
            continue;
        }

        let dir_inode = read_inode(sb, current_ino, cache, blk)?;
        if !dir_inode.is_dir() {
            return Err("not a directory in path");
        }

        match dir_lookup(sb, &dir_inode, component, cache, blk)? {
            Some(ino) => current_ino = ino,
            None => return Err("not found"),
        }
    }

    Ok(current_ino)
}

/// Iterate directory entries, calling the callback for each entry.
/// Callback receives (inode_number, file_type, name_bytes).
/// Returns Ok(()) on success.
pub fn readdir<F>(
    sb: &Superblock,
    dir_inode: &Inode,
    cache: &mut BlockCache,
    blk: &BlkClient,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(u32, u8, &[u8]),
{
    if !dir_inode.is_dir() {
        return Err("not a directory");
    }

    let dir_size = dir_inode.size as usize;
    let mut pos = 0usize;

    while pos < dir_size {
        let file_block = (pos / sb.block_size as usize) as u32;
        let disk_block = resolve_block(sb, dir_inode, file_block, cache, blk)?;
        if disk_block == 0 {
            break;
        }

        let block_data = cache.read(disk_block as u64, blk)?;
        let block_start = pos;
        let offset_in_block = pos % sb.block_size as usize;
        let mut off = offset_in_block;

        while off + 8 <= sb.block_size as usize && pos < dir_size {
            let d_inode = u32_le(block_data, off);
            let rec_len = u16_le(block_data, off + 4) as usize;
            let name_len = block_data[off + 6] as usize;
            let file_type = block_data[off + 7];

            if rec_len == 0 {
                break;
            }

            if d_inode != 0 && name_len > 0 {
                // Skip "." and ".."
                let name = &block_data[off + 8..off + 8 + name_len];
                if name != b"." && name != b".." {
                    callback(d_inode, file_type, name);
                }
            }

            off += rec_len;
            pos += rec_len;
        }

        // Advance to next block if stuck
        if pos == block_start {
            pos += sb.block_size as usize;
        }
    }

    Ok(())
}

// --- Little-endian helpers ---

fn u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}
