"""When a device registry change makes ratgdo Mgmt look at the registry again."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ratgdo_mgmt.const import DOMAIN
from homeassistant.helpers import device_registry as dr
from tests.common import probe_ok


async def _setup(hass: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Add one controller by hand and return the running coordinator."""

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        return probe_ok()

    monkeypatch.setattr("custom_components.ratgdo_mgmt.coordinator.async_probe", _probe)
    monkeypatch.setattr("custom_components.ratgdo_mgmt.config_flow.async_probe", _probe)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"host": "192.0.2.20", "port": 80, "scheme": "http", "verify_ssl": False},
    )
    await hass.async_block_till_done()
    return hass.config_entries.async_entries(DOMAIN)[0]


def _count_scans(coordinator: Any, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Replace the scan with a counter."""
    calls: list[int] = []

    async def _scan() -> None:
        calls.append(1)

    monkeypatch.setattr(coordinator, "async_scan_registry", _scan)
    return calls


def _ratgdo_row(hass: Any, url: str = "http://192.0.2.52/") -> dr.DeviceEntry:
    """Add an ESPHome ratgdo row, as the ESPHome integration would."""
    return dr.async_get(hass).async_get_or_create(
        config_entry_id=_entry(hass, "esphome").entry_id,
        identifiers={("esphome", "ratgdo")},
        connections={(dr.CONNECTION_NETWORK_MAC, "11:22:33:44:55:88")},
        manufacturer="ratgdo",
        model="v25board_esp32_secplus2",
        name="Garage",
        configuration_url=url,
    )


def _entry(hass: Any, domain: str) -> MockConfigEntry:
    """Add another integration's config entry without setting it up."""
    entry = MockConfigEntry(domain=domain, title=domain)
    entry.add_to_hass(hass)
    return entry


async def test_unrelated_devices_do_not_scan(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Devices of other integrations, and changes the scan doesn't read, are skipped."""
    entry = await _setup(hass, monkeypatch)
    calls = _count_scans(entry.runtime_data, monkeypatch)
    registry = dr.async_get(hass)

    other = _entry(hass, "hue")
    lamp = registry.async_get_or_create(
        config_entry_id=other.entry_id,
        identifiers={("hue", "lamp")},
        connections={(dr.CONNECTION_NETWORK_MAC, "11:22:33:44:55:66")},
        manufacturer="Signify",
        name="Lamp",
        configuration_url="http://192.0.2.50/",
    )
    registry.async_update_device(lamp.id, name_by_user="Desk lamp")

    esphome = _entry(hass, "esphome")
    plug = registry.async_get_or_create(
        config_entry_id=esphome.entry_id,
        identifiers={("esphome", "plug")},
        connections={(dr.CONNECTION_NETWORK_MAC, "11:22:33:44:55:77")},
        manufacturer="espressif",
        model="plug",
        name="Plug",
        configuration_url="http://192.0.2.51/",
    )
    registry.async_update_device(plug.id, sw_version="2026.10.0")
    await hass.async_block_till_done()
    assert calls == []

    ratgdo = registry.async_get_or_create(
        config_entry_id=esphome.entry_id,
        identifiers={("esphome", "ratgdo")},
        connections={(dr.CONNECTION_NETWORK_MAC, "11:22:33:44:55:88")},
        manufacturer="ratgdo",
        model="v25board_esp32_secplus2",
        name="Garage",
        configuration_url="http://192.0.2.52/",
    )
    await hass.async_block_till_done()
    assert calls == [1]

    # A firmware version or area change can't move the controller.
    registry.async_update_device(ratgdo.id, sw_version="2026.10.1")
    await hass.async_block_till_done()
    assert calls == [1]

    registry.async_update_device(ratgdo.id, configuration_url="http://192.0.2.53/")
    await hass.async_block_till_done()
    assert calls == [1, 1]


async def test_a_burst_of_changes_scans_once_more(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changes during a running scan cause one more scan, not one each."""
    entry = await _setup(hass, monkeypatch)
    coordinator = entry.runtime_data
    release = asyncio.Event()
    calls: list[int] = []

    async def _scan() -> None:
        calls.append(1)
        await release.wait()

    monkeypatch.setattr(coordinator, "async_scan_registry", _scan)
    row = _ratgdo_row(hass)
    for octet in (53, 54, 55):
        dr.async_get(hass).async_update_device(
            row.id, configuration_url=f"http://192.0.2.{octet}/"
        )
    for _ in range(5):
        await asyncio.sleep(0)
    assert calls == [1]
    release.set()
    await hass.async_block_till_done()
    assert calls == [1, 1]


async def test_unload_cancels_a_running_scan(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scan still waiting on a controller is stopped when the entry unloads."""
    entry = await _setup(hass, monkeypatch)
    coordinator = entry.runtime_data
    started = asyncio.Event()
    cancelled: list[bool] = []

    async def _scan() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    monkeypatch.setattr(coordinator, "async_scan_registry", _scan)
    _ratgdo_row(hass)
    await started.wait()
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert cancelled == [True]
