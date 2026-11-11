"""Firmware update entity.

HomeKit ``firmwareVersion`` is compared with the newest GitHub release of
``gitRepo`` (``homekit-ratgdo`` or ``homekit-ratgdo32``). ESPHome's
project version is a board profile, and ``esphome-ratgdo`` tags are build
numbers, so those are linked and not treated as the same sequence. This
entity does not install firmware. The web UI's own update page does that
for HomeKit, and the ESPHome dashboard does it for ESPHome.
"""

from __future__ import annotations

from homeassistant.components.update import UpdateEntity, UpdateEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .binary_sensor import _track
from .coordinator import RatgdoCoordinator, RatgdoMgmtConfigEntry
from .entity import RatgdoEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RatgdoMgmtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create one firmware update entity per controller."""
    _track(entry, async_add_entities, RatgdoFirmwareUpdate)


class RatgdoFirmwareUpdate(RatgdoEntity, UpdateEntity):
    """Installed version against the matching GitHub release."""

    _attr_translation_key = "firmware"
    _attr_supported_features = UpdateEntityFeature.RELEASE_NOTES

    def __init__(self, coordinator: RatgdoCoordinator, device_id: str) -> None:
        """Set the stable unique id."""
        super().__init__(coordinator, device_id)
        self._attr_unique_id = f"{device_id}_firmware"

    @property
    def installed_version(self) -> str | None:
        """Return the version the device reported."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.installed_version

    @property
    def latest_version(self) -> str | None:
        """Return a newer comparable release, or the installed version."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.update_version

    @property
    def release_url(self) -> str | None:
        """Return the GitHub release, or the releases page."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.release_notes_url

    @property
    def extra_state_attributes(self) -> dict[str, str | bool | None]:
        """Expose the raw GitHub tag when it is not comparable."""
        runtime = self.runtime
        if runtime is None:
            return {}
        return {
            "upstream_release": runtime.upstream_release,
            "update_comparable": runtime.update_available
            or (
                runtime.upstream_release is not None
                and runtime.upstream_release == runtime.installed_version
            ),
        }

    async def async_release_notes(self) -> str | None:
        """Return the GitHub release body."""
        runtime = self.runtime
        if runtime is None:
            return None
        return runtime.release_notes
