"""Default configuration values."""

import voluptuous as vol
from zigpy.config import (  # noqa: F401 pylint: disable=unused-import
    CONF_DEVICE,
    CONF_DEVICE_PATH,
    CONFIG_SCHEMA,
    SCHEMA_DEVICE,
)

CONF_WATCHDOG_TTL = "watchdog_ttl"
CONF_WATCHDOG_TTL_DEFAULT = 600

CONFIG_SCHEMA = CONFIG_SCHEMA.extend(
    {
        vol.Optional(CONF_WATCHDOG_TTL, default=CONF_WATCHDOG_TTL_DEFAULT): vol.All(
            int, vol.Range(min=180)
        )
    }
)
