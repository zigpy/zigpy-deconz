from zigpy.exceptions import ZigbeeException


class DeconzException(ZigbeeException):
    pass


class CommandError(DeconzException):
    def __init__(self, status, *args, **kwargs):
        self._status = status
        super().__init__(*args, **kwargs)

    @property
    def status(self):
        return self._status
