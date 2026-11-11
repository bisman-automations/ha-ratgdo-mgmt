"""Turn zeroconf, DHCP, and device-registry rows into ratgdo candidates.

Advertisements that are real, and what each one is for:

- ``_esphomelib._tcp`` (ESPHome ``mdns_component.cpp``, service
  ``_esphomelib``). TXT ``project_name`` is ``ratgdo.<board>`` in every
  stock ``esphome-ratgdo`` YAML. The port is the native API (6053). The
  web server, when that YAML's ``web_server:`` block is still there, is a
  second ``_http._tcp`` service. Current ESPHome does not announce
  ``_esphome._tcp``; a record of that type is still parsed the same way.
- ``_ratgdo._tcp`` (``homekit-ratgdo`` and ``homekit-ratgdo32``
  ``src/web.cpp`` ``MDNS.addService("ratgdo", "tcp", 80)``). TXT carries
  ``model``, ``firmwareVersion``, ``deviceName``, ``gitRepo``,
  ``macAddress``, and ``passwordRequired``. This is the HomeKit
  firmware's own service. The port is the web UI.
- ``_http._tcp`` on port 80 is registered by that same ``web.cpp`` and by
  ESPHome when ``web_server`` is compiled in. It is only treated as a
  candidate when the instance name looks like a stock hostname
  (``ratgdo…``, ``ratgdov…``). A random web server is not a ratgdo.
- ``_hap._tcp`` is HomeKit. HomeSpan is started with model
  ``ratgdo-ESP32`` (``homekit.cpp`` ``homeSpan.begin``). The ESP8266
  build's accessory model is ``ratgdo_v2.5`` (``ratgdo.h``). The HAP port
  is not the web port.
- DHCP hostnames follow ``name_add_mac_suffix`` (``ratgdov25-aabbcc``,
  ``ratgdo32disco-aabbcc``) and HomeKit ``make_rfc952``
  (``Garage-Door-ABCDEF``, 24 characters, spaces become dashes).

Device-registry rows are read and never written here. ESPHome copies
``project_name`` onto the device as manufacturer ``ratgdo`` and the
remainder as the model. HomeKit Controller copies the accessory
manufacturer and model. The MAC connection is how our own device later
lines up with that row.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging
from typing import Any
from urllib.parse import urlsplit

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .const import (
    BOARD_25,
    BOARD_32,
    BOARD_DISCO,
    BOARD_UNKNOWN,
    BOARD_V2,
    DEFAULT_PORT,
    ESPHOME_API_PORT,
    ESPHOME_DOMAIN,
    ESPHOME_SERVICE,
    ESPHOME_SERVICE_ALT,
    FIRMWARE_ESPHOME,
    FIRMWARE_HOMEKIT,
    GIT_REPO_ESP32,
    HAP_SERVICE,
    HOMEKIT_DOMAIN,
    HTTP_SERVICE,
    PROJECT_PREFIX,
    RATGDO_SERVICE,
    SCHEME_AUTO,
    SCHEME_HTTP,
    SCHEME_HTTPS,
)

_LOGGER = logging.getLogger(__name__)

_HOMEKIT_MANUFACTURERS = frozenset({"ratcloud llc", "ratcloud", "ratgdo"})


@dataclass(slots=True)
class Candidate:
    """A controller we might manage, before it has been probed."""

    host: str
    port: int
    scheme_mode: str = SCHEME_HTTP
    name: str | None = None
    mac: str | None = None
    node_name: str | None = None
    firmware: str | None = None
    firmware_version: str | None = None
    esphome_version: str | None = None
    project_name: str | None = None
    project_version: str | None = None
    git_repo: str | None = None
    model: str | None = None
    board: str | None = None
    api_port: int | None = None
    password_required: bool | None = None
    distance_sensor: bool | None = None
    web_port_known: bool = False
    source: str = "manual"


def normalize_mac(value: str | None) -> str | None:
    """Return a device-registry MAC, or None when the value is not one."""
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    formatted = format_mac(cleaned)
    compact = formatted.replace(":", "")
    if len(compact) != 12 or any(char not in "0123456789abcdef" for char in compact):
        return None
    return formatted


def _prop(properties: dict[str, Any], key: str) -> str | None:
    """Return one TXT value as text. Keys are matched case-insensitively."""
    value = properties.get(key)
    if value is None:
        for candidate, stored in properties.items():
            if str(candidate).lower() == key.lower():
                value = stored
                break
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    text = text.strip().strip("\x00")
    return text or None


def _bool_txt(value: str | None) -> bool | None:
    """Return a TXT boolean, or None when the key was absent."""
    if value is None:
        return None
    return value.strip().lower() == "true"


def _service(service_type: str) -> str:
    """Return a service type with a trailing dot."""
    return service_type if service_type.endswith(".") else f"{service_type}."


def _node(name: str) -> str | None:
    """Return the instance label of ``ratgdov25-aabbcc._esphomelib._tcp.local.``."""
    label = name.split(".", 1)[0].strip()
    return label or None


def classify_board(
    *,
    project_name: str | None = None,
    model: str | None = None,
    git_repo: str | None = None,
    distance_sensor: bool | None = None,
) -> str:
    """Return the board family a set of identity fields points at.

    Disco firmware is the only build that emits ``distanceSensor`` (the
    key is inside ``#ifdef RATGDO32_DISCO`` in ``build_status_json`` and
    ``add_static_mdns``). A present key means disco even when the value
    is false, because a disco board can be built without the sensor
    installed. ``v25`` is tested before ``v2`` so ``v25board`` is not
    labeled as the original v2.
    """
    haystack = " ".join(
        piece
        for piece in (project_name, model, git_repo)
        if isinstance(piece, str) and piece
    ).lower()
    if distance_sensor is not None or "disco" in haystack:
        return BOARD_DISCO
    if any(token in haystack for token in ("v25", "v2.5", "2.5")):
        return BOARD_25
    if "v2board" in haystack:
        return BOARD_V2
    if any(
        token in haystack for token in ("v32", "ratgdo_32", "ratgdo32", GIT_REPO_ESP32)
    ):
        return BOARD_32
    if haystack:
        return BOARD_UNKNOWN
    return BOARD_UNKNOWN


def _looks_like_stock_hostname(name: str | None) -> bool:
    """Return True for the hostnames the stock firmware generates."""
    if not name:
        return False
    label = name.split(".", 1)[0].strip().lower()
    if label.startswith(("ratgdo", "ratgdov")):
        return True
    return label.startswith("garage-door-")


def parse_zeroconf(info: ZeroconfServiceInfo) -> Candidate | None:
    """Return a candidate for one advertisement, or None."""
    host = str(info.host).strip("[]")
    return candidate_from_mdns(info.type, info.name, host, info.port, info.properties)


def candidate_from_mdns(
    service_type: str,
    name: str,
    host: str,
    port: int | None,
    properties: dict[str, Any],
) -> Candidate | None:
    """Return a candidate from the raw mDNS fields, or None."""
    service = _service(service_type).lower()
    properties = {str(key).lower(): value for key, value in properties.items()}
    host = host.strip("[]")
    if not host:
        return None
    node = _node(name)

    if service.startswith(("_esphomelib._tcp", "_esphome._tcp")):
        project = _prop(properties, "project_name") or ""
        name_match = _looks_like_stock_hostname(node)
        # A project name that is present and is not ratgdo.* is some other
        # ESPHome node, even if its hostname was copied from a ratgdo.
        if project and not project.startswith(PROJECT_PREFIX):
            return None
        if not project.startswith(PROJECT_PREFIX) and not name_match:
            return None
        firmware = FIRMWARE_ESPHOME if project.startswith(PROJECT_PREFIX) else None
        return Candidate(
            host=host,
            port=DEFAULT_PORT,
            scheme_mode=SCHEME_AUTO,
            name=_prop(properties, "friendly_name") or node,
            mac=normalize_mac(_prop(properties, "mac")),
            node_name=node,
            firmware=firmware,
            esphome_version=_prop(properties, "version"),
            project_name=project
            if (project or "").startswith(PROJECT_PREFIX)
            else None,
            project_version=_prop(properties, "project_version"),
            model=project.split(".", 1)[1] if project and "." in project else None,
            board=classify_board(
                project_name=project
                if (project or "").startswith(PROJECT_PREFIX)
                else None,
                model=_prop(properties, "board"),
            ),
            api_port=port or ESPHOME_API_PORT,
            web_port_known=False,
            source="zeroconf",
        )

    if service.startswith("_ratgdo._tcp"):
        model = _prop(properties, "model")
        git_repo = _prop(properties, "gitrepo")
        distance = _bool_txt(_prop(properties, "distancesensor"))
        return Candidate(
            host=host,
            port=port or DEFAULT_PORT,
            scheme_mode=SCHEME_HTTP,
            name=_prop(properties, "devicename") or node,
            mac=normalize_mac(_prop(properties, "macaddress")),
            node_name=node,
            firmware=FIRMWARE_HOMEKIT,
            firmware_version=_prop(properties, "firmwareversion"),
            git_repo=git_repo,
            model=model,
            board=classify_board(
                model=model, git_repo=git_repo, distance_sensor=distance
            ),
            password_required=_bool_txt(_prop(properties, "passwordrequired")),
            distance_sensor=distance,
            web_port_known=True,
            source="zeroconf",
        )

    if service.startswith("_hap._tcp"):
        model = _prop(properties, "md") or ""
        if "ratgdo" not in model.lower():
            return None
        return Candidate(
            host=host,
            port=DEFAULT_PORT,
            scheme_mode=SCHEME_HTTP,
            name=_prop(properties, "name") or node,
            mac=normalize_mac(_prop(properties, "id")),
            node_name=node,
            firmware=FIRMWARE_HOMEKIT,
            model=model,
            board=classify_board(model=model),
            web_port_known=False,
            source="zeroconf",
        )

    if service.startswith("_http._tcp"):
        if not _looks_like_stock_hostname(node) and not _looks_like_stock_hostname(
            host
        ):
            return None
        return Candidate(
            host=host,
            port=port or DEFAULT_PORT,
            scheme_mode=SCHEME_HTTP,
            name=node,
            node_name=node,
            web_port_known=True,
            source="zeroconf",
        )
    return None


def candidate_from_dhcp(info: DhcpServiceInfo) -> Candidate | None:
    """Return a candidate for a DHCP lease whose hostname looks like stock firmware."""
    hostname = (info.hostname or "").strip().rstrip(".")
    if not _looks_like_stock_hostname(hostname):
        return None
    ip = str(info.ip).strip("[]")
    if not ip:
        return None
    return Candidate(
        host=ip,
        port=DEFAULT_PORT,
        scheme_mode=SCHEME_AUTO,
        name=hostname.split(".", 1)[0],
        mac=normalize_mac(info.macaddress),
        node_name=hostname.split(".", 1)[0],
        web_port_known=False,
        source="dhcp",
    )


def _url_host(configuration_url: str | None) -> tuple[str | None, int, str]:
    """Return host, port, and scheme from a Visit link."""
    if not configuration_url:
        return None, DEFAULT_PORT, SCHEME_HTTP
    parts = urlsplit(configuration_url)
    if parts.hostname is None:
        return None, DEFAULT_PORT, SCHEME_HTTP
    scheme = (
        parts.scheme if parts.scheme in (SCHEME_HTTP, SCHEME_HTTPS) else SCHEME_HTTP
    )
    return parts.hostname, parts.port or DEFAULT_PORT, scheme


def _device_mac(device: dr.DeviceEntry) -> str | None:
    """Return the MAC connection on a device registry row."""
    for connection, value in device.connections:
        if connection == dr.CONNECTION_NETWORK_MAC:
            return normalize_mac(value)
    return None


def _is_esphome_ratgdo(device: dr.DeviceEntry) -> bool:
    """Return True when an ESPHome device row is a ratgdo project."""
    manufacturer = (device.manufacturer or "").lower()
    if manufacturer == "ratgdo":
        return True
    model = (device.model or "").lower()
    return model.startswith("ratgdo")


def _is_homekit_ratgdo(device: dr.DeviceEntry) -> bool:
    """Return True when a HomeKit Controller row is a ratgdo accessory."""
    model = (device.model or "").lower()
    if "ratgdo" in model:
        return True
    manufacturer = (device.manufacturer or "").lower()
    return (
        manufacturer in _HOMEKIT_MANUFACTURERS
        and "garage" in (device.name or "").lower()
    )


def candidates_from_registry(hass: HomeAssistant) -> list[Candidate]:
    """Return candidates already visible on ESPHome or HomeKit Controller rows.

    Only the row that owns the MAC is used. Sub-devices share the project
    manufacturer and have no MAC. The host comes from the Visit link.
    A HomeKit accessory often has no Visit link; mDNS still has its address,
    so a row with no host is logged and skipped.
    """
    registry = dr.async_get(hass)
    found: list[Candidate] = []
    found.extend(
        _registry_candidates(
            hass,
            registry,
            ESPHOME_DOMAIN,
            _is_esphome_ratgdo,
            FIRMWARE_ESPHOME,
        )
    )
    found.extend(
        _registry_candidates(
            hass,
            registry,
            HOMEKIT_DOMAIN,
            _is_homekit_ratgdo,
            FIRMWARE_HOMEKIT,
        )
    )
    return found


def _registry_candidates(
    hass: HomeAssistant,
    registry: dr.DeviceRegistry,
    domain: str,
    predicate: Callable[[dr.DeviceEntry], bool],
    firmware: str,
) -> list[Candidate]:
    """Return candidates for one integration's device rows."""
    found: list[Candidate] = []
    for entry in hass.config_entries.async_entries(domain):
        for device in dr.async_entries_for_config_entry(registry, entry.entry_id):
            if not predicate(device):
                continue
            mac = _device_mac(device)
            if mac is None:
                continue
            host, port, scheme = _url_host(device.configuration_url)
            if host is None:
                _LOGGER.debug(
                    "%s device %s looks like a ratgdo but has no Visit link",
                    domain,
                    device.name,
                )
                continue
            model = device.model
            project = None
            if firmware == FIRMWARE_ESPHOME and device.manufacturer and model:
                project = f"{device.manufacturer}.{model}"
            found.append(
                Candidate(
                    host=host,
                    port=port,
                    scheme_mode=scheme,
                    name=device.name,
                    mac=mac,
                    firmware=firmware,
                    project_name=project
                    if project and project.lower().startswith(PROJECT_PREFIX)
                    else None,
                    model=model,
                    board=classify_board(project_name=project, model=model),
                    web_port_known=True,
                    source="device_registry",
                )
            )
    return found


async def async_watch_mdns(
    hass: HomeAssistant,
    adopt: Callable[[Candidate], Any],
) -> Callable[[], None]:
    """Listen for ratgdo advertisements after the entry exists.

    ``single_config_entry`` makes Home Assistant drop later zeroconf flows
    before this integration can see them. The shared zeroconf instance is
    only used when that component is already running, so tests that never
    start it do not open a multicast socket.
    """
    if "zeroconf" not in hass.config.components:
        return lambda: None
    from zeroconf import ServiceBrowser, ServiceStateChange

    from homeassistant.components.zeroconf import async_get_instance

    zc = await async_get_instance(hass)

    def _handler(
        zeroconf: Any,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if state_change not in (ServiceStateChange.Added, ServiceStateChange.Updated):
            return
        info = zeroconf.get_service_info(service_type, name)
        if info is None:
            return
        addresses = info.parsed_addresses()
        if not addresses:
            return
        properties: dict[str, Any] = {}
        for key, value in info.properties.items():
            decoded_key = key.decode() if isinstance(key, bytes) else str(key)
            if isinstance(value, bytes):
                properties[decoded_key] = value.decode("utf-8", errors="replace")
            elif value is None:
                properties[decoded_key] = ""
            else:
                properties[decoded_key] = value
        candidate = candidate_from_mdns(
            service_type, name, addresses[0], info.port, properties
        )
        if candidate is None:
            return
        hass.loop.call_soon_threadsafe(
            lambda found=candidate: hass.async_create_task(adopt(found))
        )

    browser = ServiceBrowser(
        zc,
        [
            RATGDO_SERVICE,
            ESPHOME_SERVICE,
            ESPHOME_SERVICE_ALT,
            HTTP_SERVICE,
            HAP_SERVICE,
        ],
        handlers=[_handler],
    )

    def _cancel() -> None:
        browser.cancel()

    return _cancel
