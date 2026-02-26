# 0046: Map IPv6 to Unsupported in std::net backend

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** vendor/rust/library/std

## Description

The std::net PAL backend doesn't handle IPv6 addresses. If user code
attempts to use IPv6, the behavior was silently wrong (mapped to 0.0.0.0:0).

## Resolution

Changed `std_addr_to_proto()` to return `io::Result`, returning
`ErrorKind::Unsupported` with message "IPv6 is not supported on rvOS"
for any `SocketAddrV6`. Updated all 4 call sites in tcpstream.rs,
tcplistener.rs, and udp.rs to propagate the error with `?`.

Previously, IPv6 addresses were silently converted to `0.0.0.0:0`,
which would cause confusing "connection refused" or wrong-address errors.
Now callers get a clear `Unsupported` error immediately.
