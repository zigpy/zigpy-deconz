"""deCONZ serial protocol API."""

from __future__ import annotations

import asyncio
import functools
import logging
import os.path
import re

LOGGER = logging.getLogger(__name__)


def restart_forever(func, *, restart_delay=1.0):
    @functools.wraps(func)
    async def replacement(*args, **kwargs):
        while True:
            try:
                await func(*args, **kwargs)
            except Exception:
                LOGGER.debug(
                    "Endless task %s failed, restarting...", func, exc_info=True
                )

            await asyncio.sleep(restart_delay)

    return replacement


def is_usb_serial_port(device_path: str) -> bool:
    """Check if a device path is a USB serial port."""
    resolved_device = os.path.realpath(device_path)

    # Platform serial ports (Raspbee)
    if re.match(r"/dev/tty(S|AMA)\d+", resolved_device):
        return False

    # Everything else is assumed to be USB serial
    return True
