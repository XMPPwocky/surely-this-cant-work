# 0054: MCP server: screenshot save-to-file option

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** scripts/qemu-mcp

## Description

The `qemu_screenshot` MCP tool always returns image data inline as base64.
For PNG this is fine (~4KB), but PPM format produces ~4MB which exceeds
the MCP tool result size limit, causing a "result exceeds maximum allowed
tokens" error and saving to a temp file that requires manual extraction.

Even for PNG, returning base64 inline is wasteful when the caller just
wants a file on disk (e.g., to show the user via `Read`).

## Proposed Solution

Add an optional `save_path: str` parameter to `qemu_screenshot`:

- **If `save_path` is provided:** Save the screenshot to that path and
  return `{"path": "/tmp/foo.png", "size": 4036}` instead of base64 data.
  The caller can then use `Read` to view the image.
- **If `save_path` is omitted:** Current behavior (return base64 inline).

This keeps backwards compatibility while enabling the file-based workflow.

## Files

- `scripts/qemu-mcp/server.py` — modify `screenshot()` and
  `qemu_screenshot` tool to accept optional `save_path`

## Notes

The underlying QMP `screendump` command already saves to a file — the
current code saves to a temp file, reads it back, deletes it, and
base64-encodes it. With `save_path`, we can skip the read-back and just
leave the file in place.
