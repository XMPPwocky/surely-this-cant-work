# 0054: MCP server: remove PPM screenshot option or add save-to-file

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** scripts/qemu-mcp

## Description

The `qemu_screenshot` MCP tool returns image data inline as base64, which
is the standard MCP approach (`{"type": "image", "data": "<base64>",
"mimeType": "image/png"}`). For PNG this works fine (~4KB). However, PPM
format produces ~4MB of base64 which exceeds the Claude Code tool result
size limit.

## Analysis

Per the MCP spec (2025-11-25), tool results support these content types:
- `text` — plain text
- `image` — base64-encoded image with mimeType (what we use for PNG)
- `audio` — base64-encoded audio
- `resource_link` — URI the client can fetch separately

The current PNG path is correct and works well. The PPM option is the
problem — raw uncompressed bitmaps are too large for inline base64.

## Proposed Solutions (pick one)

### Option A: Just remove PPM support (simplest)
PNG is always smaller and is the default. There's no reason to offer PPM
through the MCP tool. The QMP `screendump` command can still be used
directly via `qemu_monitor` if raw PPM is needed.

### Option B: Add optional `save_path` parameter
- If `save_path` is provided: save screenshot to that path, return the
  path as text instead of base64 data. Caller uses `Read` to view it.
- If omitted: current behavior (return base64 PNG inline).

This is more flexible but adds complexity. The `qemu_monitor` +
`screendump` workaround already covers the save-to-file case (which is
how we got the working screenshot in the session where this was filed).

### Recommendation
Option A. Keep it simple.

## Files

- `scripts/qemu-mcp/server.py` — `screenshot()` method and
  `qemu_screenshot` tool registration
