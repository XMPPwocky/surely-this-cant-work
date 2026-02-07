# Kernel Conventions

## Tagged Allocators

All heap allocations in the kernel must use a tagged allocator. Never use
bare `Vec::new()` or `VecDeque::new()` — always use `Vec::new_in(TAG_ALLOC)`
or `Vec::with_capacity_in(n, TAG_ALLOC)` with the appropriate pool tag.

This ensures every allocation is tracked under a 4-byte ASCII tag visible
via the shell `mem` command. Untagged allocations show up under `????`,
which should be minimized.

Existing tags and their meanings are documented in `docs/kernel-allocator-tags.md`.

To add a new tag, define a type alias and const in `kernel/src/mm/heap.rs`:

```rust
pub type MyAlloc = TaggedAlloc<{tag(b"MYTG")}>;
pub const MY_ALLOC: MyAlloc = TaggedAlloc;
```

Then use `Vec::new_in(MY_ALLOC)` in your data structures.
