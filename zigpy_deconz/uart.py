import asyncio
import logging
import serial
import binascii

import serial_asyncio

LOGGER = logging.getLogger(__name__)


class Gateway(asyncio.Protocol):
    END = b'\xC0'
    ESC = b'\xDB'
    ESC_END = b'\xDC'
    ESC_ESC = b'\xDD'

    def __init__(self, api, connected_future=None):
        self._buffer = b''
        self._connected_future = connected_future
        self._api = api

    def connection_made(self, transport):
        """Callback when the uart is connected"""
        LOGGER.debug("Connection made")
        self._transport = transport
        if self._connected_future:
            self._connected_future.set_result(True)

    def close(self):
        self._transport.close()

    def send(self, data):
        """Send data, taking care of escaping and framing"""
        LOGGER.debug("Send: 0x%s", binascii.hexlify(data).decode())
        checksum = bytes(self._checksum(data))
        frame = self._escape(data + checksum)
        self._transport.write(self.END + frame + self.END)

    def data_received(self, data):
        """Callback when there is data received from the uart"""
        self._buffer += data
        while self._buffer:
            end = self._buffer.find(self.END)
            if end < 0:
                return None

            frame = self._buffer[:end]
            self._buffer = self._buffer[(end + 1):]
            frame = self._unescape(frame)

            if (len(frame) < 4):
                continue

            checksum = frame[-2:]
            frame = frame[:-2]
            if self._checksum(frame) != checksum:
                LOGGER.warning("Invalid checksum: 0x%s, data: 0x%s",
                               binascii.hexlify(checksum).decode(),
                               binascii.hexlify(frame).decode())
                continue

            LOGGER.debug("Frame received: 0x%s", binascii.hexlify(frame).decode())
            self._api.data_received(frame)

    def _unescape(self, data):
        ret = []
        idx = 0
        while idx < len(data):
            b = data[idx]
            if b == self.ESC[0]:
                idx += 1
                if idx >= len(data):
                    return None, None
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


async def connect(port, baudrate, api, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    connected_future = asyncio.Future()
    protocol = Gateway(api, connected_future)

    _, protocol = await serial_asyncio.create_serial_connection(
        loop,
        lambda: protocol,
        url=port,
        baudrate=baudrate,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        xonxoff=False,
    )

    await connected_future

    return protocol
