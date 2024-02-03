"""Test exceptions."""

from unittest import mock

import zigpy_deconz.exception


def test_command_error():
    ex = zigpy_deconz.exception.CommandError(
        mock.sentinel.message,
        status=mock.sentinel.status,
        command=mock.sentinel.command,
    )
    assert ex.status is mock.sentinel.status
    assert ex.command is mock.sentinel.command
