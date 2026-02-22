"""Async QMP (QEMU Machine Protocol) client.

Connects to a QEMU QMP Unix socket, performs capability negotiation,
and provides a simple execute() method for sending commands.
"""

import asyncio
import json
from typing import Any


class QMPError(Exception):
    """Error from QMP protocol."""


class QMPClient:
    """Async client for QEMU Machine Protocol over a Unix socket."""

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

    async def connect(self, sock_path: str, timeout: float = 10.0) -> dict[str, Any]:
        """Connect to the QMP socket and perform capability negotiation.

        Returns the QMP greeting message.
        """
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_unix_connection(sock_path),
            timeout=timeout,
        )
        # Read greeting
        greeting = await self._read_response(timeout=timeout)
        # Negotiate capabilities
        await self.execute("qmp_capabilities", timeout=timeout)
        return greeting

    async def execute(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute a QMP command and return the response.

        Filters out async events (stored in event_queue) and returns
        only the command response.
        """
        if self._writer is None or self._reader is None:
            raise QMPError("Not connected")

        msg: dict[str, Any] = {"execute": command}
        if arguments:
            msg["arguments"] = arguments

        data = json.dumps(msg) + "\n"
        self._writer.write(data.encode())
        await self._writer.drain()

        # Read responses, filtering out events
        while True:
            resp = await self._read_response(timeout=timeout)
            if "event" in resp:
                await self._event_queue.put(resp)
                continue
            if "error" in resp:
                raise QMPError(f"QMP error: {resp['error']}")
            return resp

    async def _read_response(self, timeout: float = 30.0) -> dict[str, Any]:
        """Read one JSON response line from QMP."""
        if self._reader is None:
            raise QMPError("Not connected")

        line = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        if not line:
            raise QMPError("QMP connection closed")
        return json.loads(line.decode())

    async def close(self) -> None:
        """Close the QMP connection."""
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None
