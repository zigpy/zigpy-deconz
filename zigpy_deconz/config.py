"""Default configuration values."""

import voluptuous as vol
from zigpy.config import (  # noqa: F401 pylint: disable=unused-import
    CONF_NWK,
    CONF_DEVICE,
    CONF_NWK_KEY,
    CONFIG_SCHEMA,
    SCHEMA_DEVICE,
    CONF_NWK_PAN_ID,
    CONF_DEVICE_PATH,
    CONF_NWK_CHANNEL,
    CONF_NWK_CHANNELS,
    CONF_NWK_UPDATE_ID,
    CONF_NWK_TC_ADDRESS,
    CONF_NWK_TC_LINK_KEY,
    CONF_NWK_EXTENDED_PAN_ID,
    cv_boolean,
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
