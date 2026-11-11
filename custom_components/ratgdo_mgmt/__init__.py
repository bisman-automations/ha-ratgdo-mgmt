"""ratgdo Mgmt: find ratgdo controllers and open their web pages."""

from __future__ import annotations

import logging

import probatio

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_DEVICE_ID,
    DOMAIN,
    SERVICE_IGNORE,
    SERVICE_REBOOT,
    SERVICE_REFRESH,
    SERVICE_REMOVE,
    SIGNAL_DEVICES_UPDATED,
)
from .coordinator import RatgdoCoordinator, async_link_devices
from .discovery import async_watch_mdns
from .panel import async_register_panel, async_unregister_panel
from .proxy import register_proxy
from .records import devices_from_options, without
from .websocket_api import async_register_websocket

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.SENSOR,
    Platform.UPDATE,
]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

type RatgdoMgmtConfigEntry = ConfigEntry[RatgdoCoordinator]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the panel script, the websocket command, and the services."""
    hass.data.setdefault(DOMAIN, {})
    # Tests construct Home Assistant without the HTTP server. A normal
    # startup has already created it before this integration loads.
    if hass.http is None:
        from homeassistant.setup import async_setup_component

        await async_setup_component(hass, "http", {})
    async_register_websocket(hass)
    register_proxy(hass)
    await async_register_panel(hass, static=True, panel=False)
    _async_register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: RatgdoMgmtConfigEntry) -> bool:
    """Set up the coordinator, entities, and sidebar panel."""
    coordinator = RatgdoCoordinator(hass, entry)
    entry.runtime_data = coordinator
    await coordinator.async_scan_registry()
    entry.async_on_unload(await async_watch_mdns(hass, coordinator.async_adopt))
    await coordinator.async_config_entry_first_refresh()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    async_link_devices(hass, coordinator)
    await async_register_panel(hass, static=False, panel=True)
    entry.async_on_unload(coordinator.async_add_listener(lambda: _dispatch(hass)))
    entry.async_on_unload(
        coordinator.async_add_listener(lambda: async_link_devices(hass, coordinator))
    )

    @callback
    def _scan_registry(_event: object) -> None:
        """Look again when Home Assistant's device list changes."""
        hass.async_create_task(coordinator.async_scan_registry())

    entry.async_on_unload(
        hass.bus.async_listen(dr.EVENT_DEVICE_REGISTRY_UPDATED, _scan_registry)
    )
    entry.async_on_unload(coordinator.async_shutdown)
    _dispatch(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: RatgdoMgmtConfigEntry) -> bool:
    """Unload entities and the sidebar panel."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        async_unregister_panel(hass)
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: RatgdoMgmtConfigEntry) -> None:
    """Drop repairs when the entry is deleted."""
    from homeassistant.helpers import issue_registry as ir

    registry = ir.async_get(hass)
    for issue in list(registry.issues.values()):
        if issue.domain == DOMAIN:
            ir.async_delete_issue(hass, DOMAIN, issue.issue_id)


@callback
def _dispatch(hass: HomeAssistant) -> None:
    """Tell websocket subscribers the list changed."""
    async_dispatcher_send(hass, SIGNAL_DEVICES_UPDATED)


def _coordinator(hass: HomeAssistant) -> RatgdoCoordinator | None:
    """Return the running coordinator, if the entry is set up."""
    for entry in hass.config_entries.async_entries(DOMAIN):
        runtime = getattr(entry, "runtime_data", None)
        if isinstance(runtime, RatgdoCoordinator):
            return runtime
    return None


def _async_register_services(hass: HomeAssistant) -> None:
    """Register the mutating services. Each one requires an admin."""
    device_schema = probatio.Schema(
        {probatio.Required(CONF_DEVICE_ID): str},
        extra=probatio.PREVENT_EXTRA,
    )
    async_register_admin_service(
        hass, DOMAIN, SERVICE_REFRESH, _async_refresh, probatio.Schema({})
    )
    async_register_admin_service(
        hass, DOMAIN, SERVICE_IGNORE, _async_ignore, device_schema
    )
    async_register_admin_service(
        hass, DOMAIN, SERVICE_REMOVE, _async_remove, device_schema
    )
    async_register_admin_service(
        hass, DOMAIN, SERVICE_REBOOT, _async_reboot, device_schema
    )


async def _async_refresh(call: ServiceCall) -> None:
    """Probe every controller now."""
    coordinator = _coordinator(call.hass)
    if coordinator is None:
        raise ServiceValidationError("ratgdo Mgmt is not set up")
    await coordinator.async_request_refresh()


async def _async_ignore(call: ServiceCall) -> None:
    """Ignore one controller."""
    await _async_mutate(call, ignore=True)


async def _async_remove(call: ServiceCall) -> None:
    """Remove one controller."""
    await _async_mutate(call, ignore=False)


async def _async_reboot(call: ServiceCall) -> None:
    """Reboot one controller."""
    coordinator = _coordinator(call.hass)
    if coordinator is None:
        raise ServiceValidationError("ratgdo Mgmt is not set up")
    device_id = str(call.data[CONF_DEVICE_ID])
    if device_id not in coordinator.records:
        raise ServiceValidationError(f"Unknown controller {device_id}")
    if not await coordinator.async_reboot(device_id):
        raise ServiceValidationError(f"Couldn't reboot {device_id}")


async def _async_mutate(call: ServiceCall, *, ignore: bool) -> None:
    """Ignore or remove a controller from the stored list."""
    coordinator = _coordinator(call.hass)
    if coordinator is None:
        raise ServiceValidationError("ratgdo Mgmt is not set up")
    device_id = str(call.data[CONF_DEVICE_ID])
    if device_id not in coordinator.records:
        raise ServiceValidationError(f"Unknown controller {device_id}")
    if ignore:
        records = devices_from_options({"devices": coordinator.records})
        records[device_id]["ignored"] = True
    else:
        records = without(coordinator.records, device_id)
    coordinator.replace_records(records)
    await coordinator.async_request_refresh()
