"""Admin-only sidebar panel.

The Lit element is built into ``frontend/ratgdo-mgmt-panel.js`` and served
from this integration. The panel requires an admin because the embedded
web UI can change the controller, including its password and firmware.
"""

from __future__ import annotations

from pathlib import Path

from homeassistant.components.frontend import (
    async_register_built_in_panel,
    async_remove_panel,
)
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import (
    DOMAIN,
    PANEL_ELEMENT,
    PANEL_ICON,
    PANEL_JS_URL,
    PANEL_TITLE,
    PANEL_URL,
)

_JS = Path(__file__).parent / "frontend" / "ratgdo-mgmt-panel.js"


async def async_register_panel(
    hass: HomeAssistant, *, static: bool, panel: bool
) -> None:
    """Register the script, the sidebar entry, or both.

    The script is registered once, from ``async_setup``. The sidebar entry
    follows the config entry so removing the integration removes the panel.
    """
    if static and not hass.data[DOMAIN].get("static"):
        await hass.http.async_register_static_paths(
            [
                StaticPathConfig(
                    PANEL_JS_URL,
                    str(_JS),
                    False,
                )
            ]
        )
        hass.data[DOMAIN]["static"] = True
    if panel:
        async_register_built_in_panel(
            hass,
            "custom",
            sidebar_title=PANEL_TITLE,
            sidebar_icon=PANEL_ICON,
            frontend_url_path=PANEL_URL,
            require_admin=True,
            update=True,
            config={
                "_panel_custom": {
                    "name": PANEL_ELEMENT,
                    "embed_iframe": False,
                    "trust_external": False,
                    "js_url": PANEL_JS_URL,
                }
            },
        )


def async_unregister_panel(hass: HomeAssistant) -> None:
    """Remove the sidebar entry. The script route can stay."""
    async_remove_panel(hass, PANEL_URL, warn_if_unknown=False)
