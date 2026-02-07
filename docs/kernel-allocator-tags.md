# Kernel Tagged Allocator

The kernel buddy-heap allocator tracks every allocation under a 4-byte
ASCII "pool tag" (inspired by Windows NT pool tags). This enables
introspection into which kernel subsystem is consuming heap memory.

## How It Works

Each allocation goes through `alloc_tagged(layout, tag)` which records the
actual buddy-block size (rounded up to a power of two) in per-tag counters.
Deallocations call `dealloc_tagged(ptr, layout, tag)` to subtract.

The `TaggedAlloc<const TAG: u32>` zero-sized type implements the nightly
`core::alloc::Allocator` trait, allowing `Vec<T, TaggedAlloc<TAG>>` and
`VecDeque<T, TaggedAlloc<TAG>>` to route through a specific tag.

Untagged allocations (via `GlobalAlloc`) are tracked under tag `????`.

## Tag Reference

| Tag    | Module                   | Tracks                                      |
|--------|--------------------------|---------------------------------------------|
| `IPC_` | `kernel/src/ipc/`        | Channel message queues (VecDeque\<Message\>) |
| `SCHD` | `kernel/src/task/`       | Process table + ready queue                  |
| `PGTB` | `kernel/src/mm/`         | Page table frame tracking                    |
| `INIT` | `kernel/src/services/`   | ELF loading data buffers                     |
| `TRAC` | `kernel/src/trace.rs`    | Trace snapshot (transient)                   |
| `????` | (global allocator)       | All untagged allocations                     |

## Viewing Memory Stats

From the shell, run:

```
rvos> mem
```

This invokes the sysinfo service's `MEMSTAT` command, which displays:

- Kernel heap summary (total, used, free)
- Per-tag breakdown (current bytes, peak bytes, live allocation count)
- Per-process physical memory usage

## Adding a New Tag

1. Define a const in `kernel/src/mm/heap.rs`:
   ```rust
   pub type MyAlloc = TaggedAlloc<{tag(b"MYTG")}>;
   pub const MY_ALLOC: MyAlloc = TaggedAlloc;
   ```

2. Use it in your data structure:
   ```rust
   let v: Vec<u8, MyAlloc> = Vec::new_in(MY_ALLOC);
   ```

3. Add the tag to the table above.
