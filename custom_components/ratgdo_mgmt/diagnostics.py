"""Diagnostics for the single ratgdo Mgmt entry.

The web password, the HomeKit pairing payload, and Wi-Fi names are
removed. Hosts and MAC addresses stay, because those are what discovery
matched on and a report without them is hard to read. Nothing here is a
Home Assistant token.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import (
    ATTR_CERT_SHA256,
    ATTR_IGNORED,
    CONF_PASSWORD,
    CONF_SCHEME,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from .coordinator import RatgdoCoordinator, RatgdoMgmtConfigEntry
from .records import devices_from_options

TO_REDACT = {
    CONF_PASSWORD,
    "password",
    "qrPayload",
    "credentials",
    "wwwCredentials",
    "wifiSSID",
    "wifiBSSID",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: RatgdoMgmtConfigEntry,
) -> dict[str, Any]:
    """Return the controller list and the last probe, with secrets removed."""
    coordinator = (
        entry.runtime_data
        if isinstance(entry.runtime_data, RatgdoCoordinator)
        else None
    )
    live = (
        {state.device_id: state for state in (coordinator.data or {}).values()}
        if coordinator
        else {}
    )
    devices: list[dict[str, Any]] = []
    for device_id, record in devices_from_options(entry.options).items():
        state = live.get(device_id)
        devices.append(
            {
                "id": device_id,
                "name": record.get("name"),
                "host": record.get("host"),
                "port": record.get("port"),
                "scheme": record.get(CONF_SCHEME),
                "scheme_mode": record.get("scheme_mode"),
                "verify_ssl": record.get(CONF_VERIFY_SSL),
                "cert_sha256": record.get(ATTR_CERT_SHA256),
                "firmware": record.get("firmware"),
                "firmware_version": record.get("firmware_version"),
                "esphome_version": record.get("esphome_version"),
                "project_name": record.get("project_name"),
                "project_version": record.get("project_version"),
                "git_repo": record.get("git_repo"),
                "model": record.get("model"),
                "board": record.get("board"),
                "mac": record.get("mac"),
                "node_name": record.get("node_name"),
                "web": record.get("web"),
                "password_required": record.get("password_required"),
                "username": record.get(CONF_USERNAME),
                "password_set": bool(record.get(CONF_PASSWORD)),
                "ignored": record.get(ATTR_IGNORED),
                "source": record.get("source"),
                "api_port": record.get("api_port"),
                "online": bool(state and state.online),
                "ssl_error": bool(state and state.ssl_error),
                "cert_mismatch": bool(state and state.cert_mismatch),
                "auth_failed": bool(state and state.auth_failed),
                "upstream_release": state.upstream_release if state else None,
                "update_available": bool(state and state.update_available),
                "uptime_ms": state.uptime_ms if state else None,
                "free_heap": state.free_heap if state else None,
                "crash_count": state.crash_count if state else None,
                "last_seen": state.last_seen.isoformat()
                if state and state.last_seen
                else None,
            }
        )
    return async_redact_data(
        {"entry_id": entry.entry_id, "devices": devices}, TO_REDACT
    )
