"""The controller list stored on the config entry.

``options["devices"]`` maps a stable id to one JSON object. The id is the
MAC when an advertisement or ``/status.json`` has one, otherwise an id
minted for a host typed by hand. A later advertisement that shares the
host fills in the MAC without changing the id, so entity unique ids stay
put when a controller changes address.

The HomeKit web password is stored on the record so the proxy can build
``X-API-Key`` and Digest for the device. Diagnostics redact it. It is
never written to a log.
"""

from __future__ import annotations

from collections.abc import Mapping
import copy
from typing import Any
from uuid import uuid4

from .client import ProbeResult, origin_url
from .const import (
    ATTR_API_PORT,
    ATTR_BOARD,
    ATTR_CERT_SHA256,
    ATTR_ESPHOME_VERSION,
    ATTR_FIRMWARE,
    ATTR_FIRMWARE_VERSION,
    ATTR_GIT_REPO,
    ATTR_IGNORED,
    ATTR_LINK_URL,
    ATTR_MAC,
    ATTR_MODEL,
    ATTR_NODE_NAME,
    ATTR_PASSWORD_REQUIRED,
    ATTR_PROJECT_NAME,
    ATTR_PROJECT_VERSION,
    ATTR_RESTART_PATH,
    ATTR_SCHEME_MODE,
    ATTR_SOURCE,
    ATTR_WEB,
    CONF_PASSWORD,
    CONF_SCHEME,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_USERNAME,
    SCHEME_AUTO,
    SCHEME_HTTP,
)
from .discovery import Candidate
from .tls import normalize_fingerprint

RECORD_KEYS = (
    "name",
    "host",
    "port",
    CONF_SCHEME,
    ATTR_SCHEME_MODE,
    CONF_VERIFY_SSL,
    ATTR_CERT_SHA256,
    ATTR_FIRMWARE,
    ATTR_FIRMWARE_VERSION,
    ATTR_ESPHOME_VERSION,
    ATTR_PROJECT_NAME,
    ATTR_PROJECT_VERSION,
    ATTR_GIT_REPO,
    ATTR_MODEL,
    ATTR_BOARD,
    ATTR_MAC,
    ATTR_NODE_NAME,
    ATTR_WEB,
    ATTR_PASSWORD_REQUIRED,
    ATTR_RESTART_PATH,
    CONF_USERNAME,
    CONF_PASSWORD,
    ATTR_IGNORED,
    ATTR_LINK_URL,
    ATTR_SOURCE,
    ATTR_API_PORT,
    "www_username",
)


def empty_options() -> dict[str, Any]:
    """Return options for a new config entry."""
    return {"devices": {}}


def devices_from_options(options: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a mutable copy of the stored device records."""
    raw = options.get("devices", {})
    if not isinstance(raw, Mapping):
        return {}
    return {
        str(device_id): _clean(record)
        for device_id, record in raw.items()
        if isinstance(record, Mapping)
    }


def _clean(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a record with the keys we persist."""
    cleaned = {key: record.get(key) for key in RECORD_KEYS}
    cleaned["port"] = int(cleaned["port"] or DEFAULT_PORT)
    cleaned[CONF_SCHEME] = cleaned[CONF_SCHEME] or SCHEME_HTTP
    cleaned[ATTR_SCHEME_MODE] = cleaned[ATTR_SCHEME_MODE] or SCHEME_AUTO
    cleaned[CONF_VERIFY_SSL] = bool(cleaned[CONF_VERIFY_SSL])
    cleaned[ATTR_IGNORED] = bool(cleaned[ATTR_IGNORED])
    cleaned[ATTR_WEB] = bool(cleaned[ATTR_WEB])
    cleaned[ATTR_PASSWORD_REQUIRED] = bool(cleaned[ATTR_PASSWORD_REQUIRED])
    if cleaned[CONF_VERIFY_SSL]:
        cleaned[ATTR_CERT_SHA256] = None
    else:
        cleaned[ATTR_CERT_SHA256] = normalize_fingerprint(cleaned.get(ATTR_CERT_SHA256))
    cleaned["name"] = cleaned["name"] or cleaned["host"]
    username = cleaned.get(CONF_USERNAME)
    cleaned[CONF_USERNAME] = (
        username.strip() if isinstance(username, str) and username.strip() else None
    )
    password = cleaned.get(CONF_PASSWORD)
    cleaned[CONF_PASSWORD] = (
        password if isinstance(password, str) and password else None
    )
    if cleaned.get(ATTR_API_PORT) is not None:
        try:
            cleaned[ATTR_API_PORT] = int(cleaned[ATTR_API_PORT])
        except TypeError, ValueError:
            cleaned[ATTR_API_PORT] = None
    return cleaned


def find_device(
    records: Mapping[str, Mapping[str, Any]],
    candidate: Candidate,
) -> str | None:
    """Return the id of the record this candidate already is, if any."""
    for device_id, record in records.items():
        if candidate.mac and record.get(ATTR_MAC) == candidate.mac:
            return device_id
    for device_id, record in records.items():
        if record.get("host") != candidate.host:
            continue
        if int(record.get("port") or 0) != candidate.port and candidate.web_port_known:
            continue
        mac = record.get(ATTR_MAC)
        if candidate.mac and mac and mac != candidate.mac:
            continue
        return device_id
    return None


def _new_id(candidate: Candidate) -> str:
    """Mint a stable id. The value is kept for the life of the record."""
    if candidate.mac:
        return f"mac:{candidate.mac}"
    return f"manual:{uuid4().hex}"


def apply_candidate(
    records: Mapping[str, Mapping[str, Any]],
    candidate: Candidate,
    probe: ProbeResult,
    *,
    verify_ssl: bool = False,
    scheme_mode: str | None = None,
    device_id: str | None = None,
    cert_sha256: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Return records with this candidate merged in.

    A failed probe does not add a device and does not move an existing
    one's address. An ignored device is left ignored. A blank password
    does not erase one that is already stored; pass the stored password
    through when the user was not asked.
    """
    updated = devices_from_options({"devices": records})
    if device_id not in updated:
        device_id = find_device(updated, candidate)
    if device_id is not None and updated[device_id][ATTR_IGNORED]:
        return updated
    if not probe.ok:
        return updated
    if device_id is None:
        device_id = _new_id(candidate)
        updated[device_id] = _clean(
            {
                "host": candidate.host,
                "port": candidate.port,
                "name": candidate.host,
                ATTR_SCHEME_MODE: scheme_mode or candidate.scheme_mode,
                CONF_VERIFY_SSL: verify_ssl,
                ATTR_SOURCE: candidate.source,
            }
        )
    record = updated[device_id]
    record["host"] = candidate.host
    # A known web port (HomeKit _ratgdo._tcp, ESPHome _http._tcp, a Visit
    # link, or a page that just answered) replaces a guessed port 80.
    if candidate.web_port_known or probe.web or not record.get("port"):
        record["port"] = candidate.port
    record[CONF_SCHEME] = probe.scheme or record[CONF_SCHEME]
    if scheme_mode is not None:
        record[ATTR_SCHEME_MODE] = scheme_mode
    elif record[ATTR_SCHEME_MODE] == SCHEME_AUTO:
        record[ATTR_SCHEME_MODE] = candidate.scheme_mode
    record[CONF_VERIFY_SSL] = (
        verify_ssl if scheme_mode is not None else record[CONF_VERIFY_SSL]
    )
    if record[CONF_VERIFY_SSL]:
        record[ATTR_CERT_SHA256] = None
    elif cert_sha256:
        record[ATTR_CERT_SHA256] = normalize_fingerprint(cert_sha256)
    elif probe.cert_sha256 and not record.get(ATTR_CERT_SHA256):
        record[ATTR_CERT_SHA256] = normalize_fingerprint(probe.cert_sha256)
    record["name"] = probe.name or candidate.name or record["name"]
    record[ATTR_FIRMWARE] = probe.firmware or record.get(ATTR_FIRMWARE)
    if probe.firmware_version:
        record[ATTR_FIRMWARE_VERSION] = probe.firmware_version
    if probe.esphome_version or candidate.esphome_version:
        record[ATTR_ESPHOME_VERSION] = (
            probe.esphome_version or candidate.esphome_version
        )
    if probe.project_name or candidate.project_name:
        record[ATTR_PROJECT_NAME] = probe.project_name or candidate.project_name
    if probe.project_version or candidate.project_version:
        record[ATTR_PROJECT_VERSION] = (
            probe.project_version or candidate.project_version
        )
    if probe.git_repo or candidate.git_repo:
        record[ATTR_GIT_REPO] = probe.git_repo or candidate.git_repo
    if probe.model or candidate.model:
        record[ATTR_MODEL] = probe.model or candidate.model
    if probe.board or candidate.board:
        record[ATTR_BOARD] = probe.board or candidate.board
    if probe.mac or candidate.mac:
        record[ATTR_MAC] = probe.mac or candidate.mac
    if candidate.node_name:
        record[ATTR_NODE_NAME] = candidate.node_name
    record[ATTR_WEB] = bool(probe.web)
    record[ATTR_PASSWORD_REQUIRED] = bool(probe.password_required)
    if probe.www_username:
        record["www_username"] = probe.www_username
    if candidate.api_port:
        record[ATTR_API_PORT] = candidate.api_port
    if username is not None:
        record[CONF_USERNAME] = username.strip() or None
    if password is not None:
        record[CONF_PASSWORD] = password or None
    record[ATTR_SOURCE] = candidate.source
    return updated


def credentials_for(record: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Return the username and password to send, or ``(None, None)``.

    A saved password with a blank username uses the firmware default
    ``admin`` (``config.cpp`` ``usernameBuf``).
    """
    password = record.get(CONF_PASSWORD)
    if not isinstance(password, str) or not password:
        return None, None
    username = record.get(CONF_USERNAME)
    if not isinstance(username, str) or not username.strip():
        username = record.get("www_username") or DEFAULT_USERNAME
    return username.strip(), password


def record_admin_url(record: Mapping[str, Any]) -> str:
    """Return the controller's own web origin."""
    link = record.get(ATTR_LINK_URL)
    if isinstance(link, str) and link.startswith(("http://", "https://")):
        return link if link.endswith("/") else f"{link}/"
    return origin_url(
        str(record.get(CONF_SCHEME) or SCHEME_HTTP),
        str(record["host"]),
        int(record["port"]),
    )


def without(
    records: Mapping[str, Mapping[str, Any]], device_id: str
) -> dict[str, dict[str, Any]]:
    """Return records without one device."""
    updated = copy.deepcopy(devices_from_options({"devices": records}))
    updated.pop(device_id, None)
    return updated
