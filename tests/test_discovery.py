"""mDNS and DHCP parsing against the firmware's records."""

from __future__ import annotations

from custom_components.ratgdo_mgmt.const import (
    BOARD_25,
    BOARD_DISCO,
    DEFAULT_PORT,
    ESPHOME_API_PORT,
    FIRMWARE_ESPHOME,
    FIRMWARE_HOMEKIT,
)
from custom_components.ratgdo_mgmt.discovery import (
    candidate_from_dhcp,
    candidate_from_mdns,
    classify_board,
    parse_zeroconf,
)
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
from tests.common import MAC, esphome_service, ratgdo_service


def test_homekit_ratgdo_service_uses_web_port_and_mac() -> None:
    """_ratgdo._tcp is the HomeKit firmware's own HTTP service."""
    candidate = parse_zeroconf(ratgdo_service())
    assert candidate is not None
    assert candidate.firmware == FIRMWARE_HOMEKIT
    assert candidate.port == 80
    assert candidate.web_port_known is True
    assert candidate.mac == MAC
    assert candidate.firmware_version == "3.5.6"
    assert candidate.git_repo == "homekit-ratgdo32"
    assert candidate.board == BOARD_DISCO
    assert candidate.password_required is True


def test_esphome_project_uses_api_port_and_web_default() -> None:
    """_esphomelib._tcp carries the API port. The web server is port 80."""
    candidate = parse_zeroconf(esphome_service())
    assert candidate is not None
    assert candidate.firmware == FIRMWARE_ESPHOME
    assert candidate.api_port == ESPHOME_API_PORT
    assert candidate.port == DEFAULT_PORT
    assert candidate.web_port_known is False
    assert candidate.project_name == "ratgdo.v25board_esp32_secplus2"
    assert candidate.project_version == "2.5"
    assert candidate.board == BOARD_25
    assert candidate.mac == MAC
    assert candidate.esphome_version == "2026.4.0"


def test_unrelated_esphome_project_is_ignored() -> None:
    """A project name that is not ratgdo.* is not a candidate."""
    assert (
        parse_zeroconf(
            esphome_service(project_name="something.else", friendly_name="Lamp")
        )
        is None
    )


def test_hap_requires_a_ratgdo_model() -> None:
    """_hap._tcp is only accepted when the model contains ratgdo."""
    found = candidate_from_mdns(
        "_hap._tcp.local.",
        "Garage._hap._tcp.local.",
        "192.0.2.20",
        5556,
        {"md": "ratgdo-ESP32", "id": MAC},
    )
    assert found is not None
    assert found.port == DEFAULT_PORT
    assert found.firmware == FIRMWARE_HOMEKIT
    other = candidate_from_mdns(
        "_hap._tcp.local.",
        "Lamp._hap._tcp.local.",
        "192.0.2.20",
        21064,
        {"md": "Lightbulb"},
    )
    assert other is None


def test_http_service_requires_a_stock_hostname() -> None:
    """A random _http._tcp server is not adopted."""
    assert (
        candidate_from_mdns(
            "_http._tcp.local.",
            "printer._http._tcp.local.",
            "192.0.2.20",
            80,
            {},
        )
        is None
    )
    found = candidate_from_mdns(
        "_http._tcp.local.",
        "ratgdo32disco-aabbcc._http._tcp.local.",
        "192.0.2.20",
        8080,
        {},
    )
    assert found is not None
    assert found.port == 8080
    assert found.web_port_known is True


def test_dhcp_hostname_and_board_classification() -> None:
    """DHCP hostnames follow the stock firmware, and disco is the distance key."""
    info = DhcpServiceInfo(
        ip="192.0.2.20",
        hostname="ratgdov25-aabbcc",
        macaddress="aabbccddeeff",
    )
    candidate = candidate_from_dhcp(info)
    assert candidate is not None
    assert candidate.mac == MAC
    assert (
        candidate_from_dhcp(
            DhcpServiceInfo(
                ip="192.0.2.20", hostname="printer", macaddress="aabbccddeeff"
            )
        )
        is None
    )
    assert (
        classify_board(project_name="ratgdo.v32disco_secplus2", distance_sensor=None)
        == BOARD_DISCO
    )
    assert classify_board(git_repo="homekit-ratgdo32", distance_sensor=False) == (
        BOARD_DISCO
    )
    assert classify_board(model="ratgdo_v2.5", git_repo="homekit-ratgdo") == BOARD_25
