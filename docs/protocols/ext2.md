# ext2 Filesystem Protocol

The **ext2-server** is a user-space process that provides read-write ext2
filesystem access backed by a VirtIO block device. It speaks the standard
filesystem protocol (`FsRequest`/`FsResponse` from `lib/rvos-proto/src/fs.rs`)
and is mounted into the VFS namespace at `/persist`.

Binary: `user/ext2-server`

Protocol definition: `lib/rvos-proto/src/fs.rs` (shared with tmpfs)

## Architecture

```
  User process         fs (tmpfs + VFS)       ext2-server         blk_server
  +-----------+      +---------------+      +-------------+      +-----------+
  | std::fs   |<---->| /tmp (tmpfs)  |      |  ext2 R/W   |<---->| VirtIO    |
  |           |      | /persist ---->|<---->|  block cache |      | blk       |
  +-----------+      +---------------+      +-------------+      +-----------+
    FS protocol        Mount/forward          FS protocol          Blk protocol
```

The ext2-server connects to a block device service (e.g., `"blk0"`) at
startup, reads the ext2 superblock, and registers itself with the VFS by
sending a `Mount` request to the tmpfs server. After mounting, all file
operations under `/persist/...` are forwarded to the ext2-server.

## Protocol

The ext2-server uses the same filesystem protocol as tmpfs. See
`docs/protocols/filesystem.md` for the full message specification. The key
operations are:

### Control Channel

| Request | Description                                      |
|---------|--------------------------------------------------|
| Open    | Open/create a file; returns a file channel cap   |
| Delete  | Delete a file or empty directory                 |
| Stat    | Get file metadata (kind, size)                   |
| Readdir | List directory entries (streaming response)       |
| Mkdir   | Create a directory                               |

### File Channel

| Request | Description                                      |
|---------|--------------------------------------------------|
| Read    | Read bytes at offset (streaming data response)   |
| Write   | Write bytes at offset                            |

## ext2-Specific Behavior

- **Block caching**: The ext2-server maintains an in-memory block cache to
  reduce disk I/O. Dirty blocks are flushed on write completion.
- **Inode/block bitmaps**: Allocation and deallocation update ext2 bitmaps
  and group descriptors on disk.
- **Read-only mode**: Passing `ro` as a command-line argument mounts the
  filesystem read-only. Write operations return `FsError::Io`.
- **Path length**: Paths within ext2 support filenames up to 255 bytes
  (ext2 limit), though the IPC message size constrains paths to what fits
  in a single `Message` payload.
- **Maximum open files**: 16 concurrent open files across all clients
  (`MAX_OPEN_FILES`). Exceeding this returns `FsError::NoSpace`.
- **Maximum clients**: 8 concurrent client connections (`MAX_CLIENTS`).

## Boot Sequence

1. Init spawns `ext2-server blk0` (or `ext2-server blk0 ro`).
2. ext2-server connects to `"blk0"`, reads superblock, validates ext2 magic.
3. ext2-server connects to `"fs"` and sends `Mount { target: "/persist" }`
   with its own control channel as a capability.
4. The tmpfs server installs the mount point. File operations under
   `/persist/` are forwarded to the ext2-server.

## Error Codes

Same as the filesystem protocol (see `docs/protocols/filesystem.md`):

| Code | Name          | Meaning                            |
|------|---------------|------------------------------------|
| 1    | NotFound      | Path does not exist                |
| 2    | AlreadyExists | File exists and EXCL was set       |
| 3    | NotAFile      | Path is a directory                |
| 4    | NotEmpty      | Directory not empty (Delete)       |
| 5    | InvalidPath   | Malformed path                     |
| 6    | NoSpace       | Disk full or open file limit       |
| 7    | Io            | Block device I/O error             |
