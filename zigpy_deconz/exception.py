"""Zigpy-deconz exceptions."""

from zigpy.exceptions import APIException


class CommandError(APIException):
    def __init__(self, status=1, *args, **kwargs):
        """Initialize instance."""
        self._status = status
        super().__init__(*args, **kwargs)

    @property
    def status(self):
        return self._status
