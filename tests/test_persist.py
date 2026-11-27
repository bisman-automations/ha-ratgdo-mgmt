"""What a probe learns about a controller is saved every time it changes."""

from __future__ import annotations

from typing import Any

import pytest

from custom_components.ratgdo_mgmt.const import DOMAIN
from tests.common import probe_ok


async def test_every_learned_change_is_saved(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second change after the first save is still saved, not only kept in memory.

    The stored options used to share the coordinator's records, so a later
    change already looked saved and Home Assistant skipped writing it.
    """
    probe = {"result": probe_ok()}

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        return probe["result"]

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
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    coordinator = entry.runtime_data

    saved: list[list[str]] = []

    async def _listener(_hass: Any, updated: Any) -> None:
        saved.append(
            [r.get("firmware_version") for r in updated.options["devices"].values()]
        )

    entry.async_on_unload(entry.add_update_listener(_listener))

    for version in ("3.6.0", "3.7.0"):
        probe["result"] = probe_ok(firmware_version=version)
        await coordinator.async_refresh()
        await hass.async_block_till_done()

    assert saved == [["3.6.0"], ["3.7.0"]]
    # The stored copy is a snapshot, not the coordinator's live records.
    assert entry.options["devices"] is not coordinator.records


async def test_changes_after_a_password_repair_are_saved(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repair hands the coordinator its own copy of the records."""
    from custom_components.ratgdo_mgmt.repairs import AuthFailedFlow  # noqa: PLC0415

    probe = {"result": probe_ok()}

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        return probe["result"]

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
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    coordinator = entry.runtime_data
    device_id = next(iter(coordinator.records))

    flow = AuthFailedFlow(entry.entry_id, device_id)
    flow.hass = hass
    await flow.async_step_init({"username": "admin", "password": "new-password"})
    assert entry.options["devices"] is not coordinator.records

    saved: list[str] = []

    async def _listener(_hass: Any, updated: Any) -> None:
        saved.append(updated.options["devices"][device_id]["firmware_version"])

    entry.async_on_unload(entry.add_update_listener(_listener))
    probe["result"] = probe_ok(firmware_version="3.8.0")
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    assert saved == ["3.8.0"]
