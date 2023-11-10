"""deCONZ serial protocol API."""

from __future__ import annotations

import asyncio
import functools
import logging

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
