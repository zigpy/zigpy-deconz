"""Uart module."""

from __future__ import annotations

import asyncio
import binascii
import logging
from typing import Any, Callable

import zigpy.config
import zigpy.serial

LOGGER = logging.getLogger(__name__)


class Gateway(zigpy.serial.SerialProtocol):
    END = b"\xC0"
    ESC = b"\xDB"
    ESC_END = b"\xDC"
    ESC_ESC = b"\xDD"

    def __init__(self, api):
        """Initialize instance of the UART gateway."""
        super().__init__()
        self._api = api

    def connection_lost(self, exc: Exception | None) -> None:
        """Port was closed expectedly or unexpectedly."""
        super().connection_lost(exc)

        if self._api is not None:
            self._api.connection_lost(exc)

    def close(self):
        super().close()
        self._api = None

    def send(self, data: bytes) -> None:
        """Send data, taking care of escaping and framing."""
        checksum = bytes(self._checksum(data))
        frame = self._escape(data + checksum)
        self._transport.write(self.END + frame + self.END)

    def data_received(self, data: bytes) -> None:
        """Handle data received from the uart."""
        super().data_received(data)

        while self._buffer:
            end = self._buffer.find(self.END)
            if end < 0:
                return None

            frame = self._buffer[:end]
            self._buffer = self._buffer[(end + 1) :]
            frame = self._unescape(frame)

            if len(frame) < 4:
                continue

            checksum = frame[-2:]
            frame = frame[:-2]
            if self._checksum(frame) != checksum:
                LOGGER.warning(
                    "Invalid checksum: 0x%s, data: 0x%s",
                    binascii.hexlify(checksum).decode(),
                    binascii.hexlify(frame).decode(),
                )
                continue

            LOGGER.debug("Frame received: 0x%s", binascii.hexlify(frame).decode())
            try:
                self._api.data_received(frame)
            except Exception as exc:
                LOGGER.error("Unexpected error handling the frame", exc_info=exc)

    def _unescape(self, data):
        ret = []
        idx = 0
        while idx < len(data):
            b = data[idx]
            if b == self.ESC[0]:
                idx += 1
                if idx >= len(data):
                    return None
                elif data[idx] == self.ESC_END[0]:
                    b = self.END[0]
                elif data[idx] == self.ESC_ESC[0]:
                    b = self.ESC[0]
            ret.append(b)
            idx += 1

        return bytes(ret)

    def _escape(self, data):
        ret = []
        for b in data:
            if b == self.END[0]:
                ret.append(self.ESC[0])
                ret.append(self.ESC_END[0])
            elif b == self.ESC[0]:
                ret.append(self.ESC[0])
                ret.append(self.ESC_ESC[0])
            else:
                ret.append(b)
        return bytes(ret)

    def _checksum(self, data):
        ret = []
        s = ~(sum(data)) + 1
        ret.append(s % 0x100)
        ret.append((s >> 8) % 0x100)
        return bytes(ret)


async def connect(config: dict[str, Any], api: Callable) -> Gateway:
    protocol = Gateway(api)

    LOGGER.debug("Connecting to %s", config[zigpy.config.CONF_DEVICE_PATH])

    _, protocol = await zigpy.serial.create_serial_connection(
        loop=asyncio.get_running_loop(),
        protocol_factory=lambda: protocol,
        url=config[zigpy.config.CONF_DEVICE_PATH],
        baudrate=config[zigpy.config.CONF_DEVICE_BAUDRATE],
        flow_control=config[zigpy.config.CONF_DEVICE_FLOW_CONTROL],
    )

    await protocol.wait_until_connected()

    return protocol
