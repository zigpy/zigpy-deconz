"""Test utils module."""

import asyncio
import logging
from unittest.mock import AsyncMock, patch

import pytest

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


@pytest.mark.parametrize(
    ("device_path", "realpath_result", "expected_is_usb"),
    [
        # Platform serial ports (Raspbee)
        ("/dev/conbee", "/dev/ttyS0", False),
        ("/dev/raspbee", "/dev/ttyAMA0", False),
        ("/dev/ttyS0", "/dev/ttyS0", False),
        ("/dev/ttyAMA0", "/dev/ttyAMA0", False),
        ("/dev/ttyS1", "/dev/ttyS1", False),
        ("/dev/ttyAMA1", "/dev/ttyAMA1", False),
        # USB serial ports (Conbee)
        ("/dev/conbee", "/dev/ttyUSB0", True),
        ("/dev/ttyUSB0", "/dev/ttyUSB0", True),
        ("/dev/ttyACM0", "/dev/ttyACM0", True),
        ("/dev/ttyUSB1", "/dev/ttyUSB1", True),
        ("/dev/ttyACM1", "/dev/ttyACM1", True),
        # Symlink to USB serial (Conbee)
        ("/dev/serial/by-id/usb-conbee", "/dev/ttyUSB0", True),
    ],
)
def test_is_usb_serial_port(device_path, realpath_result, expected_is_usb):
    """Test is_usb_serial_port with various device paths and realpath results."""
    with patch("zigpy_deconz.utils.os.path.realpath", return_value=realpath_result):
        result = utils.is_usb_serial_port(device_path)

    assert result == expected_is_usb
