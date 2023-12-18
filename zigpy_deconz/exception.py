"""Zigpy-deconz exceptions."""

from __future__ import annotations

import typing

from zigpy.exceptions import APIException

if typing.TYPE_CHECKING:
    from zigpy_deconz.api import CommandId


class CommandError(APIException):
    def __init__(self, status=1, *args, **kwargs):
        """Initialize instance."""
        self._status = status
        super().__init__(*args, **kwargs)

    @property
    def status(self):
        return self._status


class MismatchedResponseError(APIException):
    def __init__(
        self, command_id: CommandId, params: dict[str, typing.Any], *args, **kwargs
    ) -> None:
        """Initialize instance."""
        super().__init__(*args, **kwargs)
        self.command_id = command_id
        self.params = params
