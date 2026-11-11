"""Config flow: zeroconf, manual add, and options."""

from __future__ import annotations

from typing import Any

import pytest

from custom_components.ratgdo_mgmt.const import DOMAIN
from homeassistant.config_entries import SOURCE_USER, SOURCE_ZEROCONF
from tests.common import HOST, probe_fail, probe_ok, ratgdo_service


def _patch_probe(monkeypatch: pytest.MonkeyPatch, result: Any) -> None:
    """Make every flow and coordinator probe return one result."""

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        return result

    monkeypatch.setattr("custom_components.ratgdo_mgmt.config_flow.async_probe", _probe)
    monkeypatch.setattr("custom_components.ratgdo_mgmt.coordinator.async_probe", _probe)


async def test_manual_add_creates_one_entry(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Typing a host probes it and creates the single entry."""
    _patch_probe(monkeypatch, probe_ok())
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            "host": HOST,
            "port": 80,
            "scheme": "auto",
            "verify_ssl": False,
            "username": "admin",
            "password": "password",
        },
    )
    assert result["type"] == "create_entry"
    devices = result["options"]["devices"]
    assert len(devices) == 1
    record = next(iter(devices.values()))
    assert record["host"] == HOST
    assert record["firmware"] == "homekit"
    assert record["firmware_version"] == "3.5.6"
    assert record["password"] == "password"
    assert record["mac"] == "aa:bb:cc:dd:ee:ff"


async def test_manual_add_reports_errors(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed probe and a bad host stay on the form."""
    _patch_probe(monkeypatch, probe_fail())
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"host": HOST, "port": 80, "scheme": "http", "verify_ssl": False},
    )
    assert result["type"] == "form"
    assert result["errors"]["base"] == "cannot_connect"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"host": "not a host", "port": 80, "scheme": "auto", "verify_ssl": False},
    )
    assert result["errors"]["base"] == "invalid_host"


async def test_zeroconf_confirm(hass: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A _ratgdo._tcp advertisement asks before creating the entry."""
    _patch_probe(monkeypatch, probe_ok())
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=ratgdo_service()
    )
    assert result["type"] == "form"
    assert result["step_id"] == "confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == "create_entry"
    await hass.async_block_till_done()
    state = hass.states.get("binary_sensor.garage_door_abcdef_connectivity")
    assert state is not None
    assert state.state == "on"


async def test_second_discovery_aborts(
    hass: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second advertisement is folded into the entry that already exists."""
    _patch_probe(monkeypatch, probe_ok())
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"host": HOST, "port": 80, "scheme": "http", "verify_ssl": False},
    )
    assert result["type"] == "create_entry"
    await hass.async_block_till_done()
    # single_config_entry drops a later discovery flow before the integration
    # sees it. The mDNS browser in discovery.py is what adopts after that.
    again = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=ratgdo_service()
    )
    assert again["type"] == "abort"
    assert again["reason"] == "single_instance_allowed"
