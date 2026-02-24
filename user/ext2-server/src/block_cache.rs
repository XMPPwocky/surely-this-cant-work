//! LRU block cache with dirty tracking and write-back.
//!
//! Caches ext2 blocks in memory to reduce I/O to the block device.
//! Dirty blocks are written back on eviction or explicit sync.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::blk_client::BlkClient;

/// Number of cache entries.
const CACHE_SIZE: usize = 64;

/// A single cache entry holding one ext2 block.
struct CacheEntry {
    /// Block number on disk (valid only if `valid` is true).
    block_num: u64,
    /// Cached block data (heap-allocated, sized to block_size).
    data: Box<[u8]>,
    /// Whether this entry contains valid data.
    valid: bool,
    /// Whether the data has been modified since last write-back.
    dirty: bool,
    /// LRU counter (higher = more recently used).
    lru_tick: u64,
}

impl CacheEntry {
    fn new(block_size: u32) -> Self {
        let data = alloc::vec![0u8; block_size as usize].into_boxed_slice();
        CacheEntry {
            block_num: 0,
            data,
            valid: false,
            dirty: false,
            lru_tick: 0,
        }
    }
}

/// Block cache with LRU eviction and dirty write-back.
pub struct BlockCache {
    entries: Vec<CacheEntry>,
    block_size: u32,
    tick: u64,
}

impl BlockCache {
    /// Create a new block cache for the given block size.
    pub fn new(block_size: u32) -> Self {
        let mut entries = Vec::with_capacity(CACHE_SIZE);
        for _ in 0..CACHE_SIZE {
            entries.push(CacheEntry::new(block_size));
        }
        BlockCache {
            entries,
            block_size,
            tick: 0,
        }
    }

    /// Read a block, returning a reference to cached data.
    /// Fetches from disk on cache miss.
    pub fn read<'a>(&'a mut self, block_num: u64, blk: &BlkClient) -> Result<&'a [u8], &'static str> {
        self.ensure_cached(block_num, blk)?;
        let idx = self.find(block_num).unwrap();
        Ok(&self.entries[idx].data)
    }

    /// Get a mutable reference to a cached block, marking it dirty.
    /// Fetches from disk on cache miss.
    pub fn read_mut<'a>(&'a mut self, block_num: u64, blk: &BlkClient) -> Result<&'a mut [u8], &'static str> {
        self.ensure_cached(block_num, blk)?;
        let idx = self.find(block_num).unwrap();
        self.entries[idx].dirty = true;
        Ok(&mut self.entries[idx].data)
    }

    /// Write an entire block (overwrites cache, marks dirty).
    /// Does NOT read from disk first — caller provides the full block.
    #[allow(dead_code)]
    pub fn write(&mut self, block_num: u64, data: &[u8], blk: &BlkClient) -> Result<(), &'static str> {
        let idx = self.ensure_slot(block_num, blk)?;
        let entry = &mut self.entries[idx];
        entry.data[..data.len()].copy_from_slice(data);
        entry.block_num = block_num;
        entry.valid = true;
        entry.dirty = true;
        self.tick += 1;
        entry.lru_tick = self.tick;
        Ok(())
    }

    /// Flush all dirty blocks to disk.
    pub fn sync(&mut self, blk: &BlkClient) -> Result<(), &'static str> {
        for entry in &mut self.entries {
            if entry.valid && entry.dirty {
                blk.write_block(entry.block_num, self.block_size, &entry.data)?;
                entry.dirty = false;
            }
        }
        blk.flush()?;
        Ok(())
    }

    /// Invalidate all cache entries (discard without writing).
    #[allow(dead_code)]
    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
            entry.dirty = false;
        }
    }

    /// Find a cache entry for the given block number.
    fn find(&self, block_num: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.valid && e.block_num == block_num)
    }

    /// Ensure the block is in the cache. Returns the cache index.
    fn ensure_cached(&mut self, block_num: u64, blk: &BlkClient) -> Result<usize, &'static str> {
        if let Some(idx) = self.find(block_num) {
            self.tick += 1;
            self.entries[idx].lru_tick = self.tick;
            return Ok(idx);
        }
        // Cache miss — load from disk
        let idx = self.ensure_slot(block_num, blk)?;
        blk.read_block(block_num, self.block_size, &mut self.entries[idx].data)?;
        self.entries[idx].block_num = block_num;
        self.entries[idx].valid = true;
        self.entries[idx].dirty = false;
        self.tick += 1;
        self.entries[idx].lru_tick = self.tick;
        Ok(idx)
    }

    /// Get a free cache slot for `block_num`, evicting if necessary.
    /// Returns the cache index. Does NOT load data.
    fn ensure_slot(&mut self, block_num: u64, blk: &BlkClient) -> Result<usize, &'static str> {
        // Already cached?
        if let Some(idx) = self.find(block_num) {
            return Ok(idx);
        }
        // Find an empty slot
        if let Some(idx) = self.entries.iter().position(|e| !e.valid) {
            return Ok(idx);
        }
        // Evict LRU entry
        let lru_idx = self.entries.iter()
            .enumerate()
            .min_by_key(|(_, e)| e.lru_tick)
            .map(|(i, _)| i)
            .unwrap();
        // Write back if dirty
        if self.entries[lru_idx].dirty {
            blk.write_block(
                self.entries[lru_idx].block_num,
                self.block_size,
                &self.entries[lru_idx].data,
            )?;
            self.entries[lru_idx].dirty = false;
        }
        self.entries[lru_idx].valid = false;
        Ok(lru_idx)
    }
}
