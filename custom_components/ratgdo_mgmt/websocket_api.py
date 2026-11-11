"""Admin-only websocket subscription for the sidebar panel."""

from __future__ import annotations

from typing import Any

import probatio

from homeassistant.components import websocket_api
from homeassistant.components.websocket_api import ActiveConnection
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    DOMAIN,
    SIGNAL_DEVICES_UPDATED,
    SIGNED_PATH_SECONDS,
    WS_SIGN_PROXY,
)
from .coordinator import RatgdoCoordinator
from .proxy import signed_proxy_url
from .records import record_admin_url


@callback
def async_register_websocket(hass: HomeAssistant) -> None:
    """Register the subscribe command once."""
    if hass.data[DOMAIN].get("ws"):
        return
    websocket_api.async_register_command(hass, ws_subscribe)
    websocket_api.async_register_command(hass, ws_sign_proxy)
    websocket_api.async_register_command(hass, ws_set_credentials)
    hass.data[DOMAIN]["ws"] = True


def _coordinator(hass: HomeAssistant) -> RatgdoCoordinator | None:
    """Return the running coordinator."""
    for entry in hass.config_entries.async_entries(DOMAIN):
        runtime = getattr(entry, "runtime_data", None)
        if isinstance(runtime, RatgdoCoordinator):
            return runtime
    return None


def _payload(hass: HomeAssistant) -> dict[str, Any]:
    """Return the message body. Passwords are not included."""
    coordinator = _coordinator(hass)
    if coordinator is None:
        return {"devices": []}
    return {"devices": coordinator.payload()}


@websocket_api.websocket_command({probatio.Required("type"): "ratgdo_mgmt/subscribe"})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_subscribe(
    hass: HomeAssistant,
    connection: ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Stream the controller list. The result is sent first, then events."""

    @callback
    def _forward() -> None:
        connection.send_message(websocket_api.event_message(msg["id"], _payload(hass)))

    connection.subscriptions[msg["id"]] = async_dispatcher_connect(
        hass, SIGNAL_DEVICES_UPDATED, _forward
    )
    connection.send_result(msg["id"])
    _forward()


@websocket_api.websocket_command(
    {
        probatio.Required("type"): WS_SIGN_PROXY,
        probatio.Required("device_id"): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_sign_proxy(
    hass: HomeAssistant,
    connection: ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return a short-lived proxy URL for one controller.

    The signature is tied to this admin's refresh token. The panel puts it
    on the iframe and refreshes it before it expires. The first response
    sets the cookie that later requests from the embedded page send.
    """
    coordinator = _coordinator(hass)
    device_id = str(msg["device_id"])
    record = coordinator.records.get(device_id) if coordinator is not None else None
    if coordinator is None or record is None or record.get("ignored"):
        connection.send_error(msg["id"], "not_found", "Unknown controller")
        return
    if not record.get("web"):
        connection.send_error(msg["id"], "no_web", "This controller has no web page")
        return
    url = signed_proxy_url(
        hass,
        coordinator.config_entry.entry_id,
        device_id,
        refresh_token_id=connection.refresh_token_id,
    )
    connection.send_result(
        msg["id"],
        {
            "url": url,
            "expires_in": SIGNED_PATH_SECONDS,
            "direct_url": record_admin_url(record),
        },
    )


@websocket_api.websocket_command(
    {
        probatio.Required("type"): "ratgdo_mgmt/set_credentials",
        probatio.Required("device_id"): str,
        probatio.Optional(CONF_USERNAME): str,
        probatio.Required(CONF_PASSWORD): str,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def ws_set_credentials(
    hass: HomeAssistant,
    connection: ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Save the web username and password for one controller and probe again."""
    coordinator = _coordinator(hass)
    if coordinator is None:
        connection.send_error(msg["id"], "not_found", "ratgdo Mgmt is not running")
        return
    username = msg.get(CONF_USERNAME)
    error = await coordinator.async_set_web_credentials(
        str(msg["device_id"]),
        username.strip() if isinstance(username, str) else None,
        str(msg[CONF_PASSWORD]),
    )
    if error == "invalid_auth":
        connection.send_error(
            msg["id"],
            "invalid_auth",
            "That username and password were rejected.",
        )
        return
    if error:
        connection.send_error(
            msg["id"],
            error,
            "Home Assistant could not reach the controller.",
        )
        return
    connection.send_result(msg["id"], {"ok": True})
