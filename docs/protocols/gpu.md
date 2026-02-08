# GPU Protocol

The GPU server is a kernel task that wraps VirtIO GPU access. A single client
(the window server) connects via service discovery and uses this protocol to
query display info and flush framebuffer regions.

## Service Discovery

The GPU server registers as the `"gpu"` named service. Clients connect via
the boot channel:

```
BootRequest::ConnectService { name: "gpu" }
```

## Wire Format

All messages use `rvos-wire` serialization. Types are defined in
`rvos-proto::gpu`.

### Request (client → server)

```rust
define_message! {
    pub enum GpuRequest {
        GetDisplayInfo(0) {},
        Flush(1) { x: u32, y: u32, w: u32, h: u32 },
    }
}
```

**GetDisplayInfo** queries the display dimensions, pixel format, and framebuffer
SHM handle. This is typically the first request after connecting.

**Flush** tells the GPU to update a rectangular region of the display from the
framebuffer. The coordinates are in pixels.

### Response (server → client)

```rust
define_message! {
    pub enum GpuResponse {
        DisplayInfo(0) { width: u32, height: u32, stride: u32, format: u8 },
        FlushOk(1) {},
    }
}
```

**DisplayInfo** returns the display dimensions and pixel format. The message
`cap` field carries an SHM handle for the GPU framebuffer (read-write).
`format` is `0` for BGRA32.

**FlushOk** acknowledges a flush operation.

## Pixel Format

The framebuffer uses BGRA32 format (4 bytes per pixel). Each pixel is a `u32`
with layout `0xAARRGGBB` in memory (little-endian):

| Bits    | Field | Description        |
|---------|-------|--------------------|
| 31..24  | Alpha | Always 0xFF        |
| 23..16  | Red   | 0-255              |
| 15..8   | Green | 0-255              |
| 7..0    | Blue  | 0-255              |

## SHM Framebuffer

The SHM region returned by `GetDisplayInfo` maps the VirtIO GPU's framebuffer
directly. Its size is `stride * height * 4` bytes. The client writes pixels
into this buffer and then sends `Flush` to update the display.

## Connection Lifecycle

1. Client sends `GetDisplayInfo`
2. Server responds with display info + SHM capability
3. Client maps the SHM (`sys_mmap`)
4. Client writes pixels to the framebuffer
5. Client sends `Flush { x, y, w, h }` to update a region
6. Server responds with `FlushOk`
7. Repeat steps 4-6

## Example

```
Client → Server: GpuRequest::GetDisplayInfo {}
Server → Client: GpuResponse::DisplayInfo { width: 1024, height: 768, stride: 1024, format: 0 }
                 cap = <SHM handle>

Client → Server: GpuRequest::Flush { x: 0, y: 0, w: 1024, h: 768 }
Server → Client: GpuResponse::FlushOk {}
```
