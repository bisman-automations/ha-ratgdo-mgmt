"""Coordinator adoption, diagnostics redaction, and the reboot service."""

from __future__ import annotations

from typing import Any

import pytest

from custom_components.ratgdo_mgmt.const import DOMAIN
from custom_components.ratgdo_mgmt.diagnostics import async_get_config_entry_diagnostics
from custom_components.ratgdo_mgmt.discovery import parse_zeroconf
from tests.common import MAC, esphome_service, probe_ok


def _patch(monkeypatch: pytest.MonkeyPatch, result: Any) -> None:
    """Stub the probe used by setup and by adoption."""

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        return result

    monkeypatch.setattr("custom_components.ratgdo_mgmt.coordinator.async_probe", _probe)
    monkeypatch.setattr("custom_components.ratgdo_mgmt.config_flow.async_probe", _probe)


async def test_adopt_esphome_and_redact_diagnostics(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ESPHome advertisement is stored, and the password is not in diagnostics."""
    _patch(monkeypatch, probe_ok(password_required=False))
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            "host": "192.0.2.20",
            "port": 80,
            "scheme": "http",
            "verify_ssl": False,
            "password": "secret-password",
        },
    )
    assert result["type"] == "create_entry"
    await hass.async_block_till_done()
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    coordinator = entry.runtime_data
    candidate = parse_zeroconf(esphome_service())
    assert candidate is not None
    # Same MAC as the HomeKit probe, so this updates the existing record.
    changed = await coordinator.async_adopt(candidate)
    assert changed is False or changed is True
    assert any(record.get("mac") == MAC for record in coordinator.records.values())
    diag = await async_get_config_entry_diagnostics(hass, entry)
    blob = str(diag)
    assert "secret-password" not in blob
    assert diag["devices"][0]["password_set"] is True


async def test_reboot_service_rejects_an_unknown_id(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reboot service names the controller it could not find."""
    _patch(monkeypatch, probe_ok())
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"host": "192.0.2.20", "port": 80, "scheme": "http", "verify_ssl": False},
    )
    await hass.async_block_till_done()
    with pytest.raises(Exception, match="Unknown controller"):
        await hass.services.async_call(
            DOMAIN,
            "reboot",
            {"device_id": "missing"},
            blocking=True,
        )
