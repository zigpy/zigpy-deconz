from zigpy.exceptions import ZigbeeException


class DeconException(ZigbeeException):
    pass


class CommandError(DeconException):
    def __init__(self, status, *args, **kwargs):
        self._status = status
        super().__init__(*args, **kwargs)

    @property
    def status(self):
        return self._status
