"""Test utils module."""

import asyncio
import logging
from unittest.mock import AsyncMock

from zigpy_deconz import utils


async def test_restart_forever(caplog):
    mock = AsyncMock(side_effect=[None, RuntimeError(), RuntimeError(), None])
    func = utils.restart_forever(
        mock,
        restart_delay=0.1,
    )

    with caplog.at_level(logging.DEBUG):
        task = asyncio.create_task(func())
        await asyncio.sleep(0.5)
        task.cancel()

    assert caplog.text.count("failed, restarting...") >= 2
    assert caplog.text.count("RuntimeError") == 2
    assert len(mock.mock_calls) >= 4
