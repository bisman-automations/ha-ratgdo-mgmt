"""Shared entity base for one ratgdo."""

from __future__ import annotations

from typing import Any

from homeassistant.core import callback
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, FIRMWARE_ESPHOME, FIRMWARE_HOMEKIT
from .coordinator import DeviceRuntime, RatgdoCoordinator

_MANUFACTURER = {
    FIRMWARE_ESPHOME: "ratgdo",
    FIRMWARE_HOMEKIT: "ratCloud llc",
}


class RatgdoEntity(CoordinatorEntity[RatgdoCoordinator]):
    """An entity attached to one stored controller."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Bind the entity to one device id."""
        super().__init__(coordinator)
        self.device_id = device_id

    @property
    def runtime(self) -> DeviceRuntime | None:
        """Return the live view, if this controller is still managed."""
        data = self.coordinator.data
        if not data:
            return None
        return data.get(self.device_id)

    @property
    def available(self) -> bool:
        """Stay available while the controller is configured, even if it is offline.

        Connectivity has to be able to read "off". An unavailable entity would
        hide that.
        """
        return super().available and self.runtime is not None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Remove the entity when the controller is ignored or deleted."""
        if self.runtime is None:
            self.hass.async_create_task(self.async_remove())
            return
        super()._handle_coordinator_update()

    @property
    def device_info(self) -> DeviceInfo:
        """Describe our device.

        The MAC connection is what merges this row with ESPHome or HomeKit
        Controller on installs that still combine connections. On Home
        Assistant 2026.10 the rows stay separate and the coordinator sets
        ``via_device_id`` instead. Manufacturer and model are set either
        way so the row is identifiable when it does not merge.
        """
        runtime = self.runtime
        if runtime is None:
            return DeviceInfo(identifiers={(DOMAIN, self.device_id)})
        info: dict[str, Any] = {
            "identifiers": {(DOMAIN, self.device_id)},
            "name": runtime.name,
            "configuration_url": runtime.admin_url,
            "manufacturer": _MANUFACTURER.get(runtime.firmware or "", "ratgdo"),
        }
        if runtime.model:
            info["model"] = runtime.model
        if runtime.installed_version:
            info["sw_version"] = runtime.installed_version
        if runtime.mac:
            info["connections"] = {(CONNECTION_NETWORK_MAC, runtime.mac)}
        return DeviceInfo(**info)
