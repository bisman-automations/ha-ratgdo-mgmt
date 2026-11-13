"""Firmware identity and the HomeKit diagnostic counters.

Door position, light, lock, and obstruction are left to the ESPHome
integration and to HomeKit Controller. The values here come from
``/status.json`` or from the ESPHome mDNS TXT record.
"""

from __future__ import annotations

from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import (
    STATE_UNAVAILABLE,
    STATE_UNKNOWN,
    UnitOfInformation,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.util import dt as dt_util

from .binary_sensor import _track
from .const import (
    BOARD_25,
    BOARD_32,
    BOARD_DISCO,
    BOARD_UNKNOWN,
    BOARD_V2,
    BOARDS,
    FIRMWARE_HOMEKIT,
    FIRMWARES,
)
from .coordinator import RatgdoCoordinator, RatgdoMgmtConfigEntry
from .entity import RatgdoEntity

# Coordinator or push updates; nothing polls on its own.
PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RatgdoMgmtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create the identity sensors, and the HomeKit-only diagnostics."""
    for factory in (
        RatgdoFirmwareSensor,
        RatgdoFirmwareVersionSensor,
        RatgdoBoardSensor,
        RatgdoLastSeenSensor,
    ):
        _track(entry, async_add_entities, factory)
    for factory in (
        RatgdoUptimeSensor,
        RatgdoFreeHeapSensor,
        RatgdoCrashCountSensor,
    ):
        _track(entry, async_add_entities, factory, firmware=FIRMWARE_HOMEKIT)


class RatgdoFirmwareSensor(RatgdoEntity, SensorEntity):
    """ESPHome or HomeKit, from the advertisement or ``/status.json``."""

    _attr_translation_key = "firmware_type"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(FIRMWARES)
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_firmware_type"

    @property
    def native_value(self) -> str | None:
        """Return ``esphome`` or ``homekit``."""
        runtime = self.runtime
        if runtime is None or runtime.firmware not in FIRMWARES:
            return None
        return runtime.firmware

    @property
    def extra_state_attributes(self) -> dict[str, str | None]:
        """Expose the project and git repo the version was read from."""
        runtime = self.runtime
        if runtime is None:
            return {}
        return {
            "project_name": runtime.project_name,
            "git_repo": runtime.git_repo,
            "web": "yes" if runtime.web else "no",
            "esphome_version": runtime.esphome_version,
        }


class RatgdoFirmwareVersionSensor(RatgdoEntity, SensorEntity):
    """The version string the firmware itself reports.

    HomeKit ``firmwareVersion`` is the release (``2.2.6``). ESPHome
    ``project_version`` is the board profile in the YAML (``2.5``,
    ``32disco``), not the ``esphome-ratgdo`` GitHub build number.
    """

    _attr_translation_key = "firmware_version"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_firmware_version"

    @property
    def native_value(self) -> str | None:
        """Return the installed version string."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.installed_version


class RatgdoBoardSensor(RatgdoEntity, SensorEntity):
    """v2, v2.5, ratgdo32, or ratgdo32 disco, from the project or model."""

    _attr_translation_key = "board"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(BOARDS)
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_board"

    @property
    def native_value(self) -> str | None:
        """Return the board family key."""
        runtime = self.runtime
        if runtime is None or runtime.board not in {
            BOARD_V2,
            BOARD_25,
            BOARD_32,
            BOARD_DISCO,
            BOARD_UNKNOWN,
        }:
            return None
        return runtime.board


class RatgdoLastSeenSensor(RatgdoEntity, RestoreEntity, SensorEntity):
    """When a probe last succeeded. Restored so a dark boot still shows it."""

    _attr_translation_key = "last_seen"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_last_seen"
        self._restored: datetime | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the previous timestamp before the first probe returns."""
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last is None or last.state in (STATE_UNKNOWN, STATE_UNAVAILABLE):
            return
        self._restored = dt_util.parse_datetime(last.state)
        self.async_write_ha_state()

    @property
    def native_value(self) -> datetime | None:
        """Return the newest successful probe, or the restored one."""
        runtime = self.runtime
        if runtime and runtime.last_seen:
            return runtime.last_seen
        return self._restored


class _HomeKitDiagnostic(RatgdoEntity, SensorEntity):
    """A numeric field that only ``/status.json`` carries."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def available(self) -> bool:
        """Stay quiet until a HomeKit status document has been read."""
        runtime = self.runtime
        return (
            super().available
            and runtime is not None
            and runtime.firmware == FIRMWARE_HOMEKIT
            and runtime.online
        )


class RatgdoUptimeSensor(_HomeKitDiagnostic):
    """``upTime`` from ``build_status_json``, which is milliseconds."""

    _attr_translation_key = "uptime"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS
    _attr_suggested_unit_of_measurement = UnitOfTime.HOURS

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_uptime"

    @property
    def native_value(self) -> float | None:
        """Return uptime in seconds."""
        runtime = self.runtime
        if runtime is None or runtime.uptime_ms is None:
            return None
        return runtime.uptime_ms / 1000


class RatgdoFreeHeapSensor(_HomeKitDiagnostic):
    """``freeHeap`` from ``/status.json``."""

    _attr_translation_key = "free_heap"
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_native_unit_of_measurement = UnitOfInformation.BYTES
    _attr_suggested_unit_of_measurement = UnitOfInformation.KIBIBYTES

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_free_heap"

    @property
    def native_value(self) -> int | None:
        """Return free heap in bytes."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.free_heap


class RatgdoCrashCountSensor(_HomeKitDiagnostic):
    """``crashCount`` from ``/status.json``."""

    _attr_translation_key = "crash_count"

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_crash_count"

    @property
    def native_value(self) -> int | None:
        """Return the crash counter."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.crash_count
