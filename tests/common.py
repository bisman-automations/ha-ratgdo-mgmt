"""Shared fixtures for ratgdo Mgmt tests."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Any

from custom_components.ratgdo_mgmt.client import ProbeResult
from custom_components.ratgdo_mgmt.const import FIRMWARE_HOMEKIT
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

HOST = "192.0.2.20"
MAC = "aa:bb:cc:dd:ee:ff"

STATUS: dict[str, Any] = {
    "gitRepo": "homekit-ratgdo32",
    "firmwareVersion": "3.5.6",
    "deviceName": "Garage Door ABCDEF",
    "userName": "admin",
    "macAddress": "AA:BB:CC:DD:EE:FF",
    "passwordRequired": True,
    "upTime": 5000,
    "freeHeap": 80000,
    "crashCount": 0,
    "wifiRSSI": "-55 dBm, Channel 6",
    "distanceSensor": False,
}


def probe_ok(**overrides: Any) -> ProbeResult:
    """Return a successful HomeKit probe."""
    return ProbeResult(
        ok=True,
        scheme=overrides.get("scheme", "http"),
        ssl_error=False,
        firmware=overrides.get("firmware", FIRMWARE_HOMEKIT),
        name=overrides.get("name", "Garage Door ABCDEF"),
        firmware_version=overrides.get("firmware_version", "3.5.6"),
        git_repo=overrides.get("git_repo", "homekit-ratgdo32"),
        model=overrides.get("model", "ratgdo_32"),
        board=overrides.get("board", "ratgdo32_disco"),
        mac=overrides.get("mac", MAC),
        web=overrides.get("web", True),
        password_required=overrides.get("password_required", True),
        cert_sha256=overrides.get("cert_sha256"),
        cert_mismatch=bool(overrides.get("cert_mismatch", False)),
    )


def probe_fail(
    *, ssl_error: bool = False, cert_sha256: str | None = None
) -> ProbeResult:
    """Return a failed probe."""
    return ProbeResult(
        ok=False,
        scheme=None,
        ssl_error=ssl_error,
        cert_sha256=cert_sha256,
    )


def ratgdo_service(**properties: str) -> ZeroconfServiceInfo:
    """Build a _ratgdo._tcp discovery."""
    props = {
        "model": "ratgdo_32",
        "firmwareVersion": "3.5.6",
        "deviceName": "Garage Door ABCDEF",
        "gitRepo": "homekit-ratgdo32",
        "macAddress": "AA:BB:CC:DD:EE:FF",
        "passwordRequired": "true",
        "distanceSensor": "true",
    }
    props.update(properties)
    return ZeroconfServiceInfo(
        ip_address=IPv4Address(HOST),
        ip_addresses=[IPv4Address(HOST)],
        port=80,
        hostname="Garage-Door-ABCDEF.local.",
        type="_ratgdo._tcp.local.",
        name="Garage-Door-ABCDEF._ratgdo._tcp.local.",
        properties=props,
    )


def esphome_service(**properties: str) -> ZeroconfServiceInfo:
    """Build an _esphomelib._tcp discovery for a stock ratgdo project."""
    props = {
        "project_name": "ratgdo.v25board_esp32_secplus2",
        "project_version": "2.5",
        "friendly_name": "RATGDOv2.5",
        "mac": MAC,
        "version": "2026.4.0",
        "board": "wemos_d1_mini32",
    }
    props.update(properties)
    return ZeroconfServiceInfo(
        ip_address=IPv4Address(HOST),
        ip_addresses=[IPv4Address(HOST)],
        port=6053,
        hostname="ratgdov25-aabbcc.local.",
        type="_esphomelib._tcp.local.",
        name="ratgdov25-aabbcc._esphomelib._tcp.local.",
        properties=props,
    )
