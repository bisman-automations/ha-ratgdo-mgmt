"""Reboot button.

HomeKit ``POST /reboot`` is unauthenticated (``handle_reboot``). ESPHome's
stock Restart button is ``POST /button/restart/press`` and only exists
when ``web_server`` is compiled in. A headless ESPHome node keeps the
button unavailable; the ESPHome integration's own Restart button is the
one that talks to the native API.
"""

from __future__ import annotations

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .binary_sensor import _track
from .const import FIRMWARE_ESPHOME, FIRMWARE_HOMEKIT
from .coordinator import RatgdoCoordinator, RatgdoMgmtConfigEntry
from .entity import RatgdoEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RatgdoMgmtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create a reboot button for each controller."""
    _track(entry, async_add_entities, RatgdoRebootButton)


class RatgdoRebootButton(RatgdoEntity, ButtonEntity):
    """Ask the controller to reboot over HTTP."""

    _attr_translation_key = "reboot"
    _attr_device_class = ButtonDeviceClass.RESTART
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_reboot"

    @property
    def available(self) -> bool:
        """Require a route that can actually reboot the device."""
        runtime = self.runtime
        if not super().available or runtime is None or not runtime.online:
            return False
        if runtime.firmware == FIRMWARE_HOMEKIT:
            return True
        if runtime.firmware == FIRMWARE_ESPHOME:
            return runtime.web
        return False

    async def async_press(self) -> None:
        """Send the reboot request."""
        if not await self.coordinator.async_reboot(self.device_id):
            raise HomeAssistantError("Couldn't reboot the controller")
