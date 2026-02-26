# 0045: Add ext2 disk-full error path test

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** user/ext2-server, user/ktest

## Description

There was no test for what happens when an ext2 filesystem runs out of free
blocks or inodes. The error paths in ext2-server's write/create operations
returned `FsError::Io` instead of the existing `FsError::NoSpace` code.

## Resolution

Two changes:

1. **ext2-server**: Added `map_ext2_error()` helper that maps the internal
   "no space"/"no inodes" error strings to `FsError::NoSpace` instead of
   the generic `FsError::Io`. Applied to `handle_file_write`, `do_open`
   (create path), and `do_mkdir`. The `FsError::NoSpace` code (6) already
   existed in the protocol but was unused.

2. **ktest**: Added `test_ext2_disk_full` that writes 4 KB chunks to
   `/persist/diskfull` in a loop until the ext2 filesystem is full, verifies
   the error is `io::ErrorKind::StorageFull`, then cleans up and confirms
   the disk is usable after deletion.
