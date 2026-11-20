"""deCONZ serial protocol API."""

from __future__ import annotations

import asyncio
import functools
import logging
import os.path
import re
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import ParamSpec

    _P = ParamSpec("_P")

LOGGER = logging.getLogger(__name__)


def restart_forever(
    func: Callable[_P, Coroutine[Any, Any, object]], *, restart_delay: float = 1.0
) -> Callable[_P, Coroutine[Any, Any, NoReturn]]:
    @functools.wraps(func)
    async def replacement(*args: _P.args, **kwargs: _P.kwargs) -> NoReturn:
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

    # Platform serial ports (Raspbee) are not USB serial, everything else is assumed
    # to be USB serial
    return not re.match(r"/dev/tty(S|AMA)\d+", resolved_device)
