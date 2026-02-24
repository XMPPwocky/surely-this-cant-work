#!/usr/bin/env python3
"""QEMU MCP Server for rvOS agent interaction.

Provides structured tools for booting QEMU, interacting with the serial
console, taking screenshots, injecting input, and capturing network traffic.
"""

import asyncio
import atexit
import base64
import glob
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from qmp import QMPClient, QMPError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROJECT_ROOT = SCRIPT_DIR.parent.parent


def _resolve_paths(root: Path) -> tuple[Path, Path, Path]:
    """Return (kernel_bin, bin_img, persist_img) for a given project root."""
    return (
        root / "target" / "riscv64gc-unknown-none-elf" / "release" / "kernel.bin",
        root / "bin.img",
        root / "persist.img",
    )

# Temp paths include PID to avoid collisions between concurrent instances.
SERIAL_PIPE_BASE = f"/tmp/rvos-mcp-serial-{os.getpid()}"
QMP_SOCK = f"/tmp/rvos-mcp-qmp-{os.getpid()}.sock"


def _pid_alive(pid: int) -> bool:
    """Check whether a process is still running."""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _cleanup_stale_resources() -> None:
    """Remove pipes and sockets left by dead MCP server processes.

    Globs /tmp/rvos-mcp-serial-*.{in,out} and /tmp/rvos-mcp-qmp-*.sock,
    extracts the PID from the filename, and removes the file if that PID
    is no longer alive.  Skips files owned by the current process.
    """
    patterns = [
        "/tmp/rvos-mcp-serial-*.in",
        "/tmp/rvos-mcp-serial-*.out",
        "/tmp/rvos-mcp-qmp-*.sock",
    ]
    my_pid = os.getpid()
    for pat in patterns:
        for path in glob.glob(pat):
            # Extract PID from filename: e.g. /tmp/rvos-mcp-serial-12345.in
            basename = os.path.basename(path)
            try:
                # serial pipes: "rvos-mcp-serial-<pid>.in"
                # qmp sockets:  "rvos-mcp-qmp-<pid>.sock"
                parts = basename.rsplit("-", 1)  # ["rvos-mcp-serial", "12345.in"]
                pid_str = parts[1].split(".")[0]  # "12345"
                pid = int(pid_str)
            except (IndexError, ValueError):
                continue
            if pid == my_pid:
                continue
            if not _pid_alive(pid):
                try:
                    os.unlink(path)
                    sys.stderr.write(f"Removed stale resource: {path}\n")
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP("qemu-rvos", instructions=(
    "QEMU MCP server for rvOS. Use qemu_boot to start QEMU, "
    "qemu_send to run serial console commands, qemu_screenshot for "
    "display capture, and qemu_shutdown to stop."
))


class QEMUInstance:
    """Manages a single QEMU process and its communication channels."""

    def __init__(self) -> None:
        self.proc: asyncio.subprocess.Process | None = None
        self.qmp: QMPClient | None = None
        self.serial_reader_fd: int | None = None
        self.serial_writer_fd: int | None = None
        self.output_buffer: str = ""
        self._reader_task: asyncio.Task[None] | None = None
        self.boot_time: float | None = None
        self.gpu_enabled: bool = False
        self.pcap_proc: subprocess.Popen[bytes] | None = None
        self.pcap_file: str | None = None
        self._tap_name: str | None = None
        # Per-boot paths (set in boot(), default to main project root)
        self._project_root: Path = DEFAULT_PROJECT_ROOT
        self._kernel_bin: Path = Path()
        self._bin_img: Path = Path()
        self._persist_img: Path = Path()

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def _create_fifos(self) -> None:
        """Create named pipes for serial communication."""
        for suffix in (".in", ".out"):
            path = SERIAL_PIPE_BASE + suffix
            if os.path.exists(path):
                os.unlink(path)
            os.mkfifo(path)

    def _cleanup_fifos(self) -> None:
        """Remove named pipes."""
        for suffix in (".in", ".out"):
            path = SERIAL_PIPE_BASE + suffix
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def _cleanup_socket(self) -> None:
        """Remove QMP socket."""
        try:
            os.unlink(QMP_SOCK)
        except FileNotFoundError:
            pass

    async def _read_serial_loop(self) -> None:
        """Continuously read from the serial output pipe."""
        loop = asyncio.get_event_loop()
        while self.serial_reader_fd is not None:
            try:
                data = await loop.run_in_executor(
                    None, self._blocking_read_serial
                )
                if data:
                    self.output_buffer += data
            except OSError:
                break
            except asyncio.CancelledError:
                break

    def _blocking_read_serial(self) -> str:
        """Blocking read from serial pipe (runs in executor)."""
        if self.serial_reader_fd is None:
            return ""
        try:
            data = os.read(self.serial_reader_fd, 4096)
            if data:
                return data.decode("utf-8", errors="replace")
        except OSError:
            pass
        return ""

    async def boot(
        self,
        gpu: bool = False,
        network: bool = False,
        extra_drives: list[dict[str, Any]] | None = None,
        memory: str = "128M",
        wait_for_prompt: bool = True,
        project_root: str = "",
        bootargs: str | None = None,
    ) -> str:
        """Start QEMU with the given configuration."""
        if self.running:
            raise RuntimeError("QEMU is already running. Shut it down first.")

        if not project_root:
            raise RuntimeError(
                "project_root is required. Pass the absolute path to the project "
                "(or worktree) directory, e.g. '/home/ubuntu/src/temp2/rvos'."
            )

        # Resolve project root (worktree agents pass their path here)
        self._project_root = Path(project_root).resolve()
        self._kernel_bin, self._bin_img, self._persist_img = _resolve_paths(self._project_root)

        # Check kernel binary exists
        if not self._kernel_bin.exists():
            raise RuntimeError(
                f"Kernel binary not found at {self._kernel_bin}. Run 'make build' first."
            )

        # Remove stale pipes/sockets from dead server instances
        _cleanup_stale_resources()

        # Clean up any stale resources from our own PID (e.g. previous boot)
        self._cleanup_fifos()
        self._cleanup_socket()

        # Create FIFOs
        self._create_fifos()

        self.gpu_enabled = gpu

        # Build QEMU command
        cmd = [
            "qemu-system-riscv64",
            "-machine", "virt",
            "-bios", "default",
            "-m", memory,
            "-device", "virtio-keyboard-device",
            # Serial via named pipe
            "-chardev", f"pipe,id=ser0,path={SERIAL_PIPE_BASE}",
            "-serial", "chardev:ser0",
            # QMP monitor
            "-qmp", f"unix:{QMP_SOCK},server=on,wait=off",
            # Kernel
            "-kernel", str(self._kernel_bin),
        ]

        if bootargs:
            cmd.extend(["-append", bootargs])

        if gpu:
            cmd.extend([
                "-device", "virtio-gpu-device",
                "-device", "virtio-tablet-device",
                "-display", "vnc=localhost:0,to=99",
            ])
        else:
            cmd.extend(["-nographic"])

        if network:
            # Generate unique TAP name and MAC from PID
            pid = os.getpid()
            self._tap_name = f"rvos-tap-{pid}"
            mac = "52:54:00:{:02x}:{:02x}:{:02x}".format(
                (pid >> 16) & 0xFF, (pid >> 8) & 0xFF, pid & 0xFF,
            )

            # Verify bridge exists
            br_check = subprocess.run(
                ["ip", "link", "show", "rvos-br0"],
                capture_output=True,
            )
            if br_check.returncode != 0:
                raise RuntimeError(
                    "Bridge rvos-br0 not found. Run: sudo scripts/net-setup.sh"
                )

            # Create and attach TAP device
            user = os.environ.get("USER", os.environ.get("SUDO_USER", "root"))
            subprocess.run(
                ["sudo", "ip", "tuntap", "add", "dev", self._tap_name,
                 "mode", "tap", "user", user],
                check=True,
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", self._tap_name, "master", "rvos-br0"],
                check=True,
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", self._tap_name, "up"],
                check=True,
            )

            cmd.extend([
                "-device", f"virtio-net-device,netdev=net0,mac={mac}",
                "-netdev", f"tap,id=net0,ifname={self._tap_name},script=no,downscript=no",
            ])

        # Standard block devices — serial= tags let the kernel identify
        # drives regardless of MMIO probe order.
        if self._bin_img.exists():
            cmd.extend([
                "-drive", f"file={self._bin_img},format=raw,id=hd-bin,if=none,readonly=on",
                "-device", "virtio-blk-device,drive=hd-bin,serial=bin",
            ])
        if self._persist_img.exists():
            cmd.extend([
                "-drive", f"file={self._persist_img},format=raw,id=hd-persist,if=none",
                "-device", "virtio-blk-device,drive=hd-persist,serial=persist",
            ])

        # Extra drives
        if extra_drives:
            for i, drive in enumerate(extra_drives):
                drive_id = f"extra{i}"
                opts = f"file={drive['path']},format=raw,id={drive_id},if=none"
                if drive.get("readonly", False):
                    opts += ",readonly=on"
                cmd.extend([
                    "-drive", opts,
                    "-device", f"virtio-blk-device,drive={drive_id}",
                ])

        # Open serial pipe for reading BEFORE starting QEMU
        # Use O_RDWR to avoid blocking on open (pipe needs both ends)
        self.serial_reader_fd = os.open(
            SERIAL_PIPE_BASE + ".out", os.O_RDONLY | os.O_NONBLOCK
        )

        # Start QEMU
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self._project_root),
        )
        self.boot_time = time.time()
        self.output_buffer = ""

        # Start serial reader
        self._reader_task = asyncio.create_task(self._read_serial_loop())

        # Open serial write pipe
        # Use O_WRONLY — QEMU has the read end open
        await asyncio.sleep(0.5)  # Give QEMU time to open the pipe
        self.serial_writer_fd = os.open(
            SERIAL_PIPE_BASE + ".in", os.O_WRONLY | os.O_NONBLOCK
        )

        # Connect QMP
        self.qmp = QMPClient()
        try:
            await self.qmp.connect(QMP_SOCK, timeout=10.0)
        except Exception as e:
            # QMP connection failed but QEMU may still be running
            sys.stderr.write(f"QMP connect warning: {e}\n")
            self.qmp = None

        # Log actual VNC port (useful for debugging multi-instance setups)
        if gpu and self.qmp is not None:
            try:
                vnc_info = await self.qmp.execute("query-vnc", None)
                sys.stderr.write(
                    f"VNC listening on {vnc_info.get('host', '?')}:"
                    f"{vnc_info.get('service', '?')}\n"
                )
            except Exception:
                pass

        if wait_for_prompt:
            output = await self._wait_for(r"rvos>", timeout=60)
            return output
        else:
            await asyncio.sleep(2)
            return self.output_buffer

    async def send_command(
        self,
        command: str,
        timeout: int = 30,
        wait_for: str | None = None,
    ) -> str:
        """Send a command to the serial console and wait for response."""
        if not self.running:
            raise RuntimeError("QEMU is not running.")
        if self.serial_writer_fd is None:
            raise RuntimeError("Serial pipe not open.")

        pattern = wait_for or r"rvos>"

        # Clear buffer to capture only new output
        self.output_buffer = ""

        # Send command (each line terminated with \r)
        for line in command.split("\n"):
            data = (line + "\r").encode()
            os.write(self.serial_writer_fd, data)
            await asyncio.sleep(0.05)

        return await self._wait_for(pattern, timeout=timeout)

    async def read_output(
        self,
        timeout: int = 5,
        wait_for: str | None = None,
    ) -> str:
        """Read serial output without sending anything."""
        if not self.running:
            raise RuntimeError("QEMU is not running.")

        if wait_for:
            return await self._wait_for(wait_for, timeout=timeout)

        # Just wait a bit and return whatever accumulated
        await asyncio.sleep(min(timeout, 2))
        result = self.output_buffer
        self.output_buffer = ""
        return result

    async def screenshot(self, fmt: str = "png") -> tuple[str, bytes]:
        """Take a screenshot via QMP screendump.

        Returns (mime_type, image_data).
        """
        if not self.running:
            raise RuntimeError("QEMU is not running.")
        if not self.gpu_enabled:
            raise RuntimeError("Screenshots require gpu=true in qemu_boot.")
        if self.qmp is None:
            raise RuntimeError("QMP not connected.")

        suffix = ".png" if fmt == "png" else ".ppm"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            tmp_path = f.name

        try:
            await self.qmp.execute("screendump", {
                "filename": tmp_path,
                "format": fmt,
            })
            # Small delay for file to be written
            await asyncio.sleep(0.3)
            with open(tmp_path, "rb") as f:
                data = f.read()
            mime = "image/png" if fmt == "png" else "image/x-portable-pixmap"
            return mime, data
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass

    async def send_key(self, keys: str, hold_time: int = 100) -> None:
        """Send keyboard input via QMP send-key."""
        if self.qmp is None:
            raise RuntimeError("QMP not connected.")

        # Parse key combo like "ctrl-alt-delete" into list of QKeyCode entries
        key_list = [{"type": "qcode", "data": k} for k in keys.split("-")]
        await self.qmp.execute("send-key", {
            "keys": key_list,
            "hold-time": hold_time,
        })

    async def send_mouse(
        self,
        x: int,
        y: int,
        buttons: list[str] | None = None,
    ) -> None:
        """Send mouse events via QMP input-send-event."""
        if self.qmp is None:
            raise RuntimeError("QMP not connected.")

        events: list[dict[str, Any]] = [
            {"type": "abs", "data": {"axis": "x", "value": x}},
            {"type": "abs", "data": {"axis": "y", "value": y}},
        ]

        if buttons:
            button_map = {"left": 0, "right": 1, "middle": 2}
            for btn in buttons:
                btn_idx = button_map.get(btn, 0)
                events.append({
                    "type": "btn",
                    "data": {"button": f"mouse_{btn}", "down": True},
                })

        await self.qmp.execute("input-send-event", {"events": events})

        # Release buttons
        if buttons:
            release_events: list[dict[str, Any]] = []
            for btn in buttons:
                release_events.append({
                    "type": "btn",
                    "data": {"button": f"mouse_{btn}", "down": False},
                })
            await self.qmp.execute("input-send-event", {"events": release_events})

    async def monitor_command(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a raw QMP command."""
        if self.qmp is None:
            raise RuntimeError("QMP not connected.")
        return await self.qmp.execute(command, arguments)

    async def pcap_start(
        self,
        interface: str = "rvos-br0",
        filter_expr: str | None = None,
    ) -> str:
        """Start tcpdump packet capture."""
        if self.pcap_proc is not None:
            raise RuntimeError("PCAP capture already running. Stop it first.")

        with tempfile.NamedTemporaryFile(
            suffix=".pcap", delete=False, prefix="rvos-"
        ) as f:
            self.pcap_file = f.name

        cmd = ["sudo", "tcpdump", "-i", interface, "-w", self.pcap_file, "-U"]
        if filter_expr:
            cmd.extend(filter_expr.split())

        self.pcap_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # Check for early exit (e.g. permission denied, bad interface)
        try:
            self.pcap_proc.wait(timeout=0.5)
            # Process exited immediately — read stderr for error details
            stderr = ""
            if self.pcap_proc.stderr:
                stderr = self.pcap_proc.stderr.read().decode(errors="replace").strip()
            rc = self.pcap_proc.returncode
            self.pcap_proc = None
            raise RuntimeError(
                f"tcpdump exited immediately (rc={rc}): {stderr or 'no error output'}"
            )
        except subprocess.TimeoutExpired:
            # Still running after 0.5s — good, tcpdump is capturing
            pass

        return f"PCAP capture started on {interface} -> {self.pcap_file}"

    async def pcap_stop(self) -> dict[str, str]:
        """Stop tcpdump and return pcap info."""
        if self.pcap_proc is None:
            raise RuntimeError("No PCAP capture running.")

        # sudo tcpdump needs SIGTERM sent to sudo; sudo forwards it
        self.pcap_proc.terminate()
        try:
            self.pcap_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.pcap_proc.kill()
            self.pcap_proc.wait(timeout=2)

        rc = self.pcap_proc.returncode
        stderr = ""
        if self.pcap_proc.stderr:
            try:
                stderr = self.pcap_proc.stderr.read().decode(errors="replace").strip()
            except Exception:
                pass
        self.pcap_proc = None

        pcap_path = self.pcap_file or ""
        self.pcap_file = None

        size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
        result: dict[str, str] = {
            "path": pcap_path,
            "size_bytes": str(size),
        }
        if size == 0 and rc not in (None, 0, -15):
            # rc=-15 is SIGTERM (normal for tcpdump stop)
            result["warning"] = (
                f"tcpdump exited with rc={rc}, pcap file is empty. "
                f"stderr: {stderr or '(not captured)'}"
            )
        return result

    async def shutdown(self) -> str:
        """Gracefully shut down QEMU."""
        output = ""
        if self.running and self.serial_writer_fd is not None:
            try:
                os.write(self.serial_writer_fd, b"shutdown\r")
                # Wait for QEMU to exit
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=15)
                    output = self.output_buffer
                except asyncio.TimeoutError:
                    pass
            except OSError:
                pass

        # Force kill if still running
        if self.running:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self.proc.kill()
                except ProcessLookupError:
                    pass

        await self._cleanup()
        return output or "QEMU shut down."

    async def _cleanup(self) -> None:
        """Clean up all resources."""
        # Stop serial reader
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        # Close serial FDs
        if self.serial_reader_fd is not None:
            try:
                os.close(self.serial_reader_fd)
            except OSError:
                pass
            self.serial_reader_fd = None

        if self.serial_writer_fd is not None:
            try:
                os.close(self.serial_writer_fd)
            except OSError:
                pass
            self.serial_writer_fd = None

        # Close QMP
        if self.qmp is not None:
            await self.qmp.close()
            self.qmp = None

        # Stop pcap
        if self.pcap_proc is not None:
            self.pcap_proc.terminate()
            try:
                self.pcap_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.pcap_proc.kill()
            self.pcap_proc = None

        # Clean up temp files
        self._cleanup_fifos()
        self._cleanup_socket()

        # Destroy dynamic TAP device
        if self._tap_name is not None:
            try:
                subprocess.run(
                    ["sudo", "ip", "tuntap", "del", "dev", self._tap_name,
                     "mode", "tap"],
                    check=False, capture_output=True,
                )
            except Exception:
                pass
            self._tap_name = None

        self.proc = None
        self.boot_time = None

    async def _wait_for(self, pattern: str, timeout: int = 30) -> str:
        """Wait for a regex pattern to appear in serial output."""
        compiled = re.compile(pattern)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if compiled.search(self.output_buffer):
                result = self.output_buffer
                self.output_buffer = ""
                return result
            await asyncio.sleep(0.1)

        # Timeout — return what we have
        result = self.output_buffer
        self.output_buffer = ""
        return f"[TIMEOUT waiting for /{pattern}/]\n{result}"


# Singleton QEMU instance
qemu = QEMUInstance()

# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------


@mcp.tool()
async def qemu_boot(
    project_root: str,
    gpu: bool = False,
    network: bool = False,
    extra_drives: list[dict[str, Any]] | None = None,
    memory: str = "128M",
    wait_for_prompt: bool = True,
    bootargs: str | None = None,
) -> str:
    """Start QEMU with rvOS.

    Args:
        project_root: Absolute path to the project (or worktree) directory.
                      Required — ensures correct kernel.bin, bin.img, persist.img.
        gpu: Enable virtio-gpu + VNC display (needed for screenshots)
        network: Enable TAP networking
        extra_drives: Additional block devices [{path, readonly}]
        memory: RAM size (default 128M)
        wait_for_prompt: Wait for rvos> prompt before returning
        bootargs: Kernel boot arguments (e.g. "no-watchdog", "watchdog=30")

    Returns: Boot log up to first prompt (or timeout).
    """
    return await qemu.boot(
        project_root=project_root,
        gpu=gpu,
        network=network,
        extra_drives=extra_drives,
        memory=memory,
        wait_for_prompt=wait_for_prompt,
        bootargs=bootargs,
    )


@mcp.tool()
async def qemu_send(
    command: str,
    timeout: int = 30,
    wait_for: str | None = None,
) -> str:
    """Send a command to the rvOS serial console.

    Args:
        command: Text to send (multi-line OK; each line sent with \\r)
        timeout: Seconds to wait for response (default 30)
        wait_for: Regex to wait for (default: rvos>)

    Returns: All output between send and the wait_for match.
    """
    return await qemu.send_command(command, timeout=timeout, wait_for=wait_for)


@mcp.tool()
async def qemu_read(
    timeout: int = 5,
    wait_for: str | None = None,
) -> str:
    """Read current serial output without sending anything.

    Args:
        timeout: Seconds to wait for output (default 5)
        wait_for: Regex to stop at (optional)

    Returns: Accumulated output.
    """
    return await qemu.read_output(timeout=timeout, wait_for=wait_for)


@mcp.tool()
async def qemu_screenshot(format: str = "png") -> list[dict[str, Any]]:
    """Take a screenshot of the VNC display.

    Requires: QEMU booted with gpu=true.

    Args:
        format: Image format — "png" or "ppm" (default png)

    Returns: Screenshot image data.
    """
    mime, data = await qemu.screenshot(fmt=format)
    return [
        {
            "type": "image",
            "data": base64.b64encode(data).decode(),
            "mimeType": mime,
        }
    ]


@mcp.tool()
async def qemu_send_key(
    keys: str,
    hold_time: int = 100,
) -> str:
    """Send keyboard input via QMP.

    Args:
        keys: Key combo like "ctrl-alt-delete", "shift-a", "ret"
        hold_time: Hold duration in ms (default 100)

    Returns: Confirmation.
    """
    await qemu.send_key(keys, hold_time=hold_time)
    return f"Sent key: {keys}"


@mcp.tool()
async def qemu_mouse(
    x: int,
    y: int,
    buttons: list[str] | None = None,
) -> str:
    """Send mouse events via QMP.

    Args:
        x: Absolute X position (0-32767)
        y: Absolute Y position (0-32767)
        buttons: Buttons to click: "left", "right", "middle"

    Returns: Confirmation.
    """
    await qemu.send_mouse(x, y, buttons=buttons)
    btn_str = f" + click {buttons}" if buttons else ""
    return f"Mouse moved to ({x}, {y}){btn_str}"


@mcp.tool()
async def qemu_monitor(
    command: str,
    arguments: dict[str, Any] | None = None,
) -> str:
    """Send a raw QMP command to the QEMU monitor.

    Args:
        command: QMP execute command name
        arguments: Command arguments (optional)

    Returns: QMP response as JSON string.
    """
    import json
    result = await qemu.monitor_command(command, arguments)
    return json.dumps(result, indent=2)


@mcp.tool()
async def qemu_pcap_start(
    interface: str = "rvos-br0",
    filter: str | None = None,
) -> str:
    """Start capturing network traffic with tcpdump.

    Args:
        interface: Network interface (default rvos-br0)
        filter: tcpdump filter expression (optional)

    Returns: Confirmation with output file path.
    """
    return await qemu.pcap_start(interface=interface, filter_expr=filter)


@mcp.tool()
async def qemu_pcap_stop() -> str:
    """Stop PCAP capture.

    Returns: Path to pcap file and size.
    """
    import json
    result = await qemu.pcap_stop()
    return json.dumps(result, indent=2)


@mcp.tool()
async def qemu_shutdown() -> str:
    """Gracefully shut down QEMU.

    Sends 'shutdown' to serial, waits for exit, cleans up FIFOs/sockets.

    Returns: Final output or confirmation.
    """
    return await qemu.shutdown()


@mcp.tool()
async def qemu_status() -> str:
    """Check if QEMU is running.

    Returns: Status, uptime, PID.
    """
    import json
    if qemu.running:
        uptime = time.time() - (qemu.boot_time or time.time())
        info = {
            "status": "running",
            "pid": qemu.proc.pid,
            "uptime_seconds": round(uptime, 1),
            "gpu": qemu.gpu_enabled,
            "pcap_active": qemu.pcap_proc is not None,
        }
    else:
        info = {"status": "stopped"}
    return json.dumps(info, indent=2)


# ---------------------------------------------------------------------------
# Cleanup on server exit
# ---------------------------------------------------------------------------

def _sync_cleanup() -> None:
    """Synchronous cleanup of pipes, socket, and QEMU process.

    Suitable for atexit and signal handlers where the async event loop may
    not be available.
    """
    # Kill QEMU if still running
    if qemu.proc is not None and qemu.proc.returncode is None:
        sys.stderr.write("MCP server exiting — killing QEMU...\n")
        try:
            qemu.proc.terminate()
        except ProcessLookupError:
            pass

    # Close serial FDs
    for fd in (qemu.serial_reader_fd, qemu.serial_writer_fd):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    qemu.serial_reader_fd = None
    qemu.serial_writer_fd = None

    # Stop pcap
    if qemu.pcap_proc is not None:
        try:
            qemu.pcap_proc.terminate()
        except ProcessLookupError:
            pass
        qemu.pcap_proc = None

    # Remove pipes and socket
    qemu._cleanup_fifos()
    qemu._cleanup_socket()

    # Destroy dynamic TAP device
    if qemu._tap_name is not None:
        try:
            subprocess.run(
                ["sudo", "ip", "tuntap", "del", "dev", qemu._tap_name,
                 "mode", "tap"],
                check=False, capture_output=True,
            )
        except Exception:
            pass
        qemu._tap_name = None


# Register synchronous cleanup for normal interpreter exit
atexit.register(_sync_cleanup)


def _signal_handler(sig: int, _frame: Any) -> None:
    """Handle SIGTERM/SIGINT with synchronous cleanup, then exit."""
    _sync_cleanup()
    sys.exit(128 + sig)


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
