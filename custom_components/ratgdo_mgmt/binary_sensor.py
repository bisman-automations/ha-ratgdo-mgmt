"""Connectivity, and whether the HomeKit web UI is asking for a password."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import FIRMWARE_HOMEKIT
from .coordinator import RatgdoCoordinator, RatgdoMgmtConfigEntry
from .entity import RatgdoEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RatgdoMgmtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create sensors for each controller, including ones found later."""
    _track(entry, async_add_entities, RatgdoConnectivityBinarySensor)
    _track(
        entry,
        async_add_entities,
        RatgdoPasswordRequiredBinarySensor,
        firmware=FIRMWARE_HOMEKIT,
    )


def _track(
    entry: RatgdoMgmtConfigEntry,
    async_add_entities: AddEntitiesCallback,
    factory: type[RatgdoEntity],
    *,
    firmware: str | None = None,
) -> None:
    """Add an entity whenever a device id shows up in the coordinator."""
    coordinator = entry.runtime_data
    known: set[str] = set()

    def _sync() -> None:
        fresh: list[RatgdoEntity] = []
        for device_id, runtime in (coordinator.data or {}).items():
            if device_id in known:
                continue
            if firmware is not None and runtime.firmware != firmware:
                continue
            fresh.append(factory(coordinator, device_id))
            known.add(device_id)
        if fresh:
            async_add_entities(fresh)

    entry.async_on_unload(coordinator.async_add_listener(_sync))
    _sync()


class RatgdoConnectivityBinarySensor(RatgdoEntity, BinarySensorEntity):
    """On while the web port, or the ESPHome advertisement, answered."""

    _attr_translation_key = "connectivity"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_connectivity"

    @property
    def is_on(self) -> bool:
        """Return True when the last probe reached the controller."""
        runtime = self.runtime
        return bool(runtime and runtime.online)


class RatgdoPasswordRequiredBinarySensor(RatgdoEntity, BinarySensorEntity):
    """On when HomeKit firmware has ``passwordRequired`` set.

    ``/status.json`` reports the flag with no credentials. The door
    entities from HomeKit Controller are a different thing; this only
    says whether the web UI will ask before changing settings.
    """

    _attr_translation_key = "password_required"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_password_required"

    @property
    def is_on(self) -> bool:
        """Return True when the web UI is protecting settings."""
        runtime = self.runtime
        return bool(runtime and runtime.password_required)
