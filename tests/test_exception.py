from unittest import mock

import zigpy_deconz.exception


def test_command_error():
    ex = zigpy_deconz.exception.CommandError(
        mock.sentinel.status, mock.sentinel.message
    )
    assert ex.status is mock.sentinel.status
