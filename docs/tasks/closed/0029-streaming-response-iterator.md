# 0029: Add streaming response iterator to lib/rvos

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** lib/rvos, ipc

## Problem

Several protocols use multi-message responses terminated by a zero-length
sentinel: sysinfo sends lines until `len==0`, readdir sends entries until
`len==0`. Callers must manually loop:

```rust
loop {
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(handle, &mut resp);
    if resp.len == 0 { break; }
    io::stdout().write_all(&resp.data[..resp.len]).ok();
}
```

This pattern appears in `shell.rs` (sysinfo), and the two-phase readdir
handling in `fs` and `ext2-server`. A reusable iterator would make these
one-liners.

See: Architecture Review 8, section 4 ("MEDIUM: Streaming Response
Iterator").

## Proposed API

```rust
// lib/rvos/src/channel.rs (addition)

pub struct StreamReceiver<'a, R: MessageType> {
    channel: &'a mut RawChannel,
    buf: Box<Message>,
    done: bool,
    _phantom: PhantomData<R>,
}

impl<R: MessageType> Iterator for StreamReceiver<'_, R> {
    type Item = Result<R::Msg<'_>, RecvError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done { return None; }
        match recv_blocking into self.buf {
            Ok(msg) if msg.len == 0 => { self.done = true; None }
            Ok(msg) => Some(decode(msg)),
            Err(RecvError::Closed) => { self.done = true; None }
            Err(e) => Some(Err(e)),
        }
    }
}
```

Usage:
```rust
for line in sysinfo_chan.recv_stream::<SysinfoLine>() {
    print!("{}", line?);
}
```

Note: The GAT lifetime on `R::Msg<'_>` makes this tricky — the iterator
item borrows from `self.buf`, which conflicts with `Iterator`'s signature.
May need a callback-based API (`recv_stream_foreach`) or a lending-iterator
pattern instead.

## Acceptance Criteria

1. Streaming recv API added to `lib/rvos/src/channel.rs`.
2. Shell's `send_sysinfo_cmd()` converted to use it.
3. API handles the GAT lifetime constraint (callback or lending iterator).
4. `make build` + `make clippy` clean.
5. `make test-quick` passes.
