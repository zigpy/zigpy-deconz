"""Zigpy-deconz exceptions."""

from __future__ import annotations

import typing

from zigpy.exceptions import APIException

if typing.TYPE_CHECKING:
    from zigpy_deconz.api import Command, CommandId, Status


class CommandError(APIException):
    def __init__(self, *args, status: Status, command: Command, **kwargs):
        """Initialize instance."""
        super().__init__(*args, **kwargs)
        self.command = command
        self.status = status


class ParsingError(CommandError):
    pass


class MismatchedResponseError(APIException):
    def __init__(
        self, command_id: CommandId, params: dict[str, typing.Any], *args, **kwargs
    ) -> None:
        """Initialize instance."""
        super().__init__(*args, **kwargs)
        self.command_id = command_id
        self.params = params
