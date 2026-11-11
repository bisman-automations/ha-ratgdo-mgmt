"""Polling, adoption, releases, and repairs for every ratgdo we manage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, issue_registry as ir
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .client import ProbeResult, async_discover_restart_path, async_probe, async_reboot
from .const import (
    ATTR_API_PORT,
    ATTR_BOARD,
    ATTR_CERT_SHA256,
    ATTR_ESPHOME_VERSION,
    ATTR_FIRMWARE,
    ATTR_FIRMWARE_VERSION,
    ATTR_GIT_REPO,
    ATTR_IGNORED,
    ATTR_MAC,
    ATTR_MODEL,
    ATTR_PASSWORD_REQUIRED,
    ATTR_PROJECT_NAME,
    ATTR_PROJECT_VERSION,
    ATTR_RESTART_PATH,
    ATTR_SCHEME_MODE,
    ATTR_WEB,
    CONF_PASSWORD,
    CONF_SCHEME,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DOMAIN,
    ESPHOME_DOMAIN,
    FIRMWARE_ESPHOME,
    FIRMWARE_HOMEKIT,
    HOMEKIT_DOMAIN,
    SCHEME_AUTO,
    SIGNAL_DEVICES_UPDATED,
    UPDATE_INTERVAL,
)
from .discovery import Candidate, candidates_from_registry
from .records import (
    apply_candidate,
    credentials_for,
    devices_from_options,
    find_device,
    record_admin_url,
)
from .releases import (
    ReleaseInfo,
    async_fetch_latest,
    is_newer,
    latest_for_entity,
    release_url,
    repo_for,
    stale,
)
from .tls import format_fingerprint, normalize_fingerprint

_LOGGER = logging.getLogger(__name__)

type RatgdoMgmtConfigEntry = ConfigEntry["RatgdoCoordinator"]


@dataclass(slots=True)
class DeviceRuntime:
    """Live view of one controller. ``last_seen`` stays set across a failed probe."""

    device_id: str
    name: str
    host: str
    port: int
    scheme: str
    scheme_mode: str
    verify_ssl: bool
    firmware: str | None
    firmware_version: str | None
    esphome_version: str | None
    project_name: str | None
    project_version: str | None
    git_repo: str | None
    model: str | None
    board: str | None
    mac: str | None
    web: bool
    password_required: bool
    online: bool
    last_seen: datetime | None
    ssl_error: bool
    cert_mismatch: bool
    presented_sha256: str | None
    auth_failed: bool
    www_username: str | None
    wifi_rssi: str | None
    uptime_ms: int | None
    free_heap: int | None
    crash_count: int | None
    api_port: int | None
    ignored: bool
    latest_version: str | None
    release_notes_url: str | None
    release_notes: str | None
    upstream_release: str | None

    @property
    def admin_url(self) -> str:
        """Return the page the panel opens directly."""
        return record_admin_url(
            {
                "host": self.host,
                "port": self.port,
                CONF_SCHEME: self.scheme,
            }
        )

    @property
    def installed_version(self) -> str | None:
        """Return the version the update entity compares."""
        if self.firmware == FIRMWARE_HOMEKIT:
            return self.firmware_version
        return self.project_version or self.firmware_version

    @property
    def update_version(self) -> str | None:
        """Return latest when it is comparable, else the installed version."""
        return latest_for_entity(self.installed_version, self.upstream_release)

    @property
    def update_available(self) -> bool:
        """Return True only when the GitHub tag is a newer version of the same kind."""
        return is_newer(self.installed_version, self.upstream_release)


def runtime_from_record(
    device_id: str,
    record: dict[str, Any],
    probe: ProbeResult | None,
    previous: DeviceRuntime | None,
    release: ReleaseInfo | None,
) -> DeviceRuntime:
    """Build the live view from a stored record and the latest probe."""
    online = bool(probe and probe.ok)
    last_seen = previous.last_seen if previous else None
    if online:
        last_seen = dt_util.utcnow()
    scheme = record.get(CONF_SCHEME) or (probe.scheme if probe else None) or "http"
    notes = release.notes if release else None
    upstream = release.version if release else None
    url = (
        release.url
        if release
        else release_url(record.get(ATTR_FIRMWARE), record.get(ATTR_GIT_REPO))
    )
    return DeviceRuntime(
        device_id=device_id,
        name=str(record.get("name") or record["host"]),
        host=str(record["host"]),
        port=int(record.get("port") or DEFAULT_PORT),
        scheme=str(scheme),
        scheme_mode=str(record.get(ATTR_SCHEME_MODE) or SCHEME_AUTO),
        verify_ssl=bool(record.get(CONF_VERIFY_SSL)),
        firmware=record.get(ATTR_FIRMWARE),
        firmware_version=record.get(ATTR_FIRMWARE_VERSION),
        esphome_version=record.get(ATTR_ESPHOME_VERSION),
        project_name=record.get(ATTR_PROJECT_NAME),
        project_version=record.get(ATTR_PROJECT_VERSION),
        git_repo=record.get(ATTR_GIT_REPO),
        model=record.get(ATTR_MODEL),
        board=record.get(ATTR_BOARD),
        mac=record.get(ATTR_MAC),
        web=bool(record.get(ATTR_WEB)),
        password_required=bool(record.get(ATTR_PASSWORD_REQUIRED)),
        online=online,
        last_seen=last_seen,
        ssl_error=bool(probe and probe.ssl_error and not online),
        cert_mismatch=bool(probe and probe.cert_mismatch and not online),
        presented_sha256=probe.cert_sha256 if probe else None,
        auth_failed=bool(probe and probe.auth_failed and online),
        www_username=(
            probe.www_username
            if probe and probe.www_username
            else record.get("www_username")
        ),
        wifi_rssi=probe.wifi_rssi if probe and probe.ok else None,
        uptime_ms=probe.uptime_ms if probe and probe.ok else None,
        free_heap=probe.free_heap if probe and probe.ok else None,
        crash_count=probe.crash_count if probe and probe.ok else None,
        api_port=record.get(ATTR_API_PORT),
        ignored=bool(record.get(ATTR_IGNORED)),
        latest_version=latest_for_entity(
            record.get(ATTR_FIRMWARE_VERSION)
            if record.get(ATTR_FIRMWARE) == FIRMWARE_HOMEKIT
            else record.get(ATTR_PROJECT_VERSION) or record.get(ATTR_FIRMWARE_VERSION),
            upstream,
        ),
        release_notes_url=url,
        release_notes=notes,
        upstream_release=upstream,
    )


class RatgdoCoordinator(DataUpdateCoordinator[dict[str, DeviceRuntime]]):
    """Probe each controller and publish the list to entities and the panel."""

    config_entry: RatgdoMgmtConfigEntry

    def __init__(self, hass: HomeAssistant, entry: RatgdoMgmtConfigEntry) -> None:
        """Load the stored controllers and start the poll interval."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )
        self.config_entry = entry
        self.records = devices_from_options(entry.options)
        self.releases: dict[str, ReleaseInfo] = {}

    async def _async_update_data(self) -> dict[str, DeviceRuntime]:
        """Probe every controller that is not ignored, then refresh releases."""
        previous = self.data or {}
        probed: dict[str, ProbeResult] = {}
        for device_id, record in self.records.items():
            if record.get(ATTR_IGNORED):
                continue
            username, password = credentials_for(record)
            hint = _hint_from_record(record)
            probe = await async_probe(
                self.hass,
                str(record["host"]),
                int(record.get("port") or DEFAULT_PORT),
                str(record.get(ATTR_SCHEME_MODE) or SCHEME_AUTO),
                bool(record.get(CONF_VERIFY_SSL)),
                preferred=str(record.get(CONF_SCHEME) or "") or None,
                pinned_sha256=record.get(ATTR_CERT_SHA256),
                hint=hint,
                username=username,
                password=password,
            )
            had_restart = record.get(ATTR_RESTART_PATH)
            if (
                probe.web
                and probe.firmware == FIRMWARE_ESPHOME
                and not probe.auth_failed
                and not had_restart
            ):
                path = await async_discover_restart_path(
                    self.hass,
                    scheme=str(probe.scheme or record.get(CONF_SCHEME) or "http"),
                    host=str(record["host"]),
                    port=int(record.get("port") or DEFAULT_PORT),
                    verify_ssl=bool(record.get(CONF_VERIFY_SSL)),
                    pinned_sha256=record.get(ATTR_CERT_SHA256),
                    username=username,
                    password=password,
                )
                if path:
                    record[ATTR_RESTART_PATH] = path
            self._absorb_probe(record, probe)
            if record.get(ATTR_RESTART_PATH) != had_restart:
                self._persist()
            probed[device_id] = probe
        await self._async_refresh_releases()
        current = {
            device_id: runtime_from_record(
                device_id,
                record,
                probed.get(device_id),
                previous.get(device_id),
                self._release_for(record),
            )
            for device_id, record in self.records.items()
            if not record.get(ATTR_IGNORED)
        }
        self._sync_repairs(current)
        return current

    def _absorb_probe(self, record: dict[str, Any], probe: ProbeResult) -> None:
        """Copy identity from a good probe onto the stored record."""
        if (
            probe.ok
            and not record.get(CONF_VERIFY_SSL)
            and probe.cert_sha256
            and not record.get(ATTR_CERT_SHA256)
            and probe.scheme == "https"
        ):
            record[ATTR_CERT_SHA256] = normalize_fingerprint(probe.cert_sha256)
            self._persist()
        if not probe.ok:
            return
        changed = False
        for key, value in (
            (CONF_SCHEME, probe.scheme),
            ("name", probe.name),
            (ATTR_FIRMWARE, probe.firmware),
            (ATTR_FIRMWARE_VERSION, probe.firmware_version),
            (ATTR_ESPHOME_VERSION, probe.esphome_version),
            (ATTR_PROJECT_NAME, probe.project_name),
            (ATTR_PROJECT_VERSION, probe.project_version),
            (ATTR_GIT_REPO, probe.git_repo),
            (ATTR_MODEL, probe.model),
            (ATTR_BOARD, probe.board),
            (ATTR_MAC, probe.mac),
            ("www_username", probe.www_username),
        ):
            if value and record.get(key) != value:
                record[key] = value
                changed = True
        if record.get(ATTR_WEB) != probe.web:
            record[ATTR_WEB] = probe.web
            changed = True
        if record.get(ATTR_PASSWORD_REQUIRED) != probe.password_required:
            record[ATTR_PASSWORD_REQUIRED] = probe.password_required
            changed = True
        if changed:
            self._persist()

    async def _async_refresh_releases(self) -> None:
        """Fetch each firmware repo at most once per ``RELEASE_INTERVAL``."""
        now = dt_util.utcnow()
        needed: set[str] = set()
        for record in self.records.values():
            if record.get(ATTR_IGNORED):
                continue
            repo = repo_for(record.get(ATTR_FIRMWARE), record.get(ATTR_GIT_REPO))
            if repo and stale(self.releases.get(repo), now):
                needed.add(repo)
        for repo in sorted(needed):
            info = await async_fetch_latest(self.hass, repo)
            if info is not None:
                self.releases[repo] = info
                _LOGGER.debug("Latest %s release is %s", repo, info.version)

    def _release_for(self, record: dict[str, Any]) -> ReleaseInfo | None:
        """Return the cached release for this record's firmware."""
        repo = repo_for(record.get(ATTR_FIRMWARE), record.get(ATTR_GIT_REPO))
        if repo is None:
            return None
        return self.releases.get(repo)

    @callback
    def _persist(self) -> None:
        """Write the records back without reloading the entry."""
        self.hass.config_entries.async_update_entry(
            self.config_entry,
            options={"devices": self.records},
        )

    def replace_records(self, records: dict[str, dict[str, Any]]) -> None:
        """Replace the stored list and tell listeners."""
        self.records = records
        self._persist()
        async_dispatcher_send(self.hass, SIGNAL_DEVICES_UPDATED)

    async def async_adopt(
        self,
        candidate: Candidate,
        *,
        verify_ssl: bool = False,
        scheme_mode: str | None = None,
        refresh: bool = True,
    ) -> bool:
        """Probe a candidate and keep it when it is a ratgdo.

        Returns True when the stored list changed. Ignored controllers are
        not brought back.
        """
        existing = find_device(self.records, candidate)
        if existing is not None and self.records[existing].get(ATTR_IGNORED):
            return False
        record = self.records.get(existing) if existing else None
        use_verify = (
            verify_ssl
            if scheme_mode is not None
            else bool((record or {}).get(CONF_VERIFY_SSL, verify_ssl))
        )
        username, password = credentials_for(record) if record else (None, None)
        probe = await async_probe(
            self.hass,
            candidate.host,
            candidate.port,
            scheme_mode
            or (record or {}).get(ATTR_SCHEME_MODE)
            or candidate.scheme_mode,
            use_verify,
            pinned_sha256=(record or {}).get(ATTR_CERT_SHA256),
            hint=candidate,
            username=username,
            password=password,
        )
        merged = apply_candidate(
            self.records,
            candidate,
            probe,
            verify_ssl=use_verify,
            scheme_mode=scheme_mode,
            cert_sha256=probe.cert_sha256 if probe.ok else None,
            username=username,
            password=password,
        )
        if merged == self.records:
            return False
        self.records = merged
        self._persist()
        if refresh and self.data is not None:
            await self.async_request_refresh()
        return True

    async def async_scan_registry(self) -> None:
        """Adopt ratgdo rows already in the device registry."""
        changed = False
        for candidate in candidates_from_registry(self.hass):
            if await self.async_adopt(candidate, refresh=False):
                changed = True
        if changed and self.data is not None:
            await self.async_request_refresh()
            _LOGGER.debug("Device registry scan added or moved a ratgdo")

    async def async_set_web_credentials(
        self, device_id: str, username: str | None, password: str
    ) -> str | None:
        """Store a web username and password, then probe.

        Returns an error key, or None when the controller accepted them.
        The password is the ESPHome ``web_server`` ``auth`` password or the
        HomeKit web password. It is not logged.
        """
        record = self.records.get(device_id)
        if record is None or record.get(ATTR_IGNORED) or not password:
            return "invalid_auth"
        record[CONF_USERNAME] = username.strip() if username else None
        record[CONF_PASSWORD] = password
        self._persist()
        await self.async_request_refresh()
        state = (self.data or {}).get(device_id)
        if state is None or not state.online:
            return "cannot_connect"
        if state.auth_failed:
            return "invalid_auth"
        return None

    async def async_reboot(self, device_id: str) -> bool:
        """Reboot one controller. The caller has already checked it exists."""
        record = self.records.get(device_id)
        if record is None or record.get(ATTR_IGNORED):
            return False
        if record.get(ATTR_FIRMWARE) == FIRMWARE_ESPHOME and not record.get(ATTR_WEB):
            _LOGGER.debug(
                "Not rebooting %s over HTTP; its ESPHome build has no web_server",
                device_id,
            )
            return False
        username, password = credentials_for(record)
        esphome_path = record.get(ATTR_RESTART_PATH)
        if record.get(ATTR_FIRMWARE) == FIRMWARE_ESPHOME and not esphome_path:
            esphome_path = await async_discover_restart_path(
                self.hass,
                scheme=str(record.get(CONF_SCHEME) or "http"),
                host=str(record["host"]),
                port=int(record.get("port") or DEFAULT_PORT),
                verify_ssl=bool(record.get(CONF_VERIFY_SSL)),
                pinned_sha256=record.get(ATTR_CERT_SHA256),
                username=username,
                password=password,
            )
            if esphome_path:
                record[ATTR_RESTART_PATH] = esphome_path
                self._persist()
        return await async_reboot(
            self.hass,
            scheme=str(record.get(CONF_SCHEME) or "http"),
            host=str(record["host"]),
            port=int(record.get("port") or DEFAULT_PORT),
            firmware=str(record.get(ATTR_FIRMWARE) or ""),
            verify_ssl=bool(record.get(CONF_VERIFY_SSL)),
            pinned_sha256=record.get(ATTR_CERT_SHA256),
            username=username,
            password=password,
            esphome_path=esphome_path if isinstance(esphome_path, str) else None,
        )

    @callback
    def _sync_repairs(self, current: dict[str, DeviceRuntime]) -> None:
        """Raise a repair while a controller is offline, mismatched, or rejected."""
        seen: set[str] = set()
        for state in current.values():
            placeholders = {"name": state.name, "host": state.host}
            kinds = ("offline", "certificate", "certificate_changed", "auth_failed")
            ids = {kind: _issue_id(kind, state.device_id) for kind in kinds}
            seen.update(ids.values())
            if state.online and not state.auth_failed:
                for issue_id in ids.values():
                    ir.async_delete_issue(self.hass, DOMAIN, issue_id)
                continue
            if state.cert_mismatch:
                self._certificate_changed(state, ids, placeholders)
                continue
            ir.async_delete_issue(self.hass, DOMAIN, ids["certificate_changed"])
            if state.ssl_error:
                ir.async_delete_issue(self.hass, DOMAIN, ids["offline"])
                ir.async_delete_issue(self.hass, DOMAIN, ids["auth_failed"])
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    ids["certificate"],
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key="certificate",
                    translation_placeholders=placeholders,
                )
                continue
            ir.async_delete_issue(self.hass, DOMAIN, ids["certificate"])
            if state.auth_failed:
                ir.async_delete_issue(self.hass, DOMAIN, ids["offline"])
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    ids["auth_failed"],
                    is_fixable=True,
                    severity=ir.IssueSeverity.ERROR,
                    translation_key="auth_failed",
                    translation_placeholders=placeholders,
                    data={
                        "entry_id": self.config_entry.entry_id,
                        "device_id": state.device_id,
                    },
                )
                continue
            ir.async_delete_issue(self.hass, DOMAIN, ids["auth_failed"])
            if not state.online:
                ir.async_create_issue(
                    self.hass,
                    DOMAIN,
                    ids["offline"],
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key="offline",
                    translation_placeholders=placeholders,
                )
        registry = ir.async_get(self.hass)
        for issue in list(registry.issues.values()):
            if issue.domain != DOMAIN or issue.issue_id in seen:
                continue
            if issue.issue_id.startswith(("offline_", "certificate_", "auth_failed_")):
                ir.async_delete_issue(self.hass, DOMAIN, issue.issue_id)

    def _certificate_changed(
        self,
        state: DeviceRuntime,
        ids: dict[str, str],
        placeholders: dict[str, str],
    ) -> None:
        """Raise the fixable certificate repair and clear the others."""
        ir.async_delete_issue(self.hass, DOMAIN, ids["offline"])
        ir.async_delete_issue(self.hass, DOMAIN, ids["certificate"])
        ir.async_delete_issue(self.hass, DOMAIN, ids["auth_failed"])
        stored = normalize_fingerprint(
            self.records.get(state.device_id, {}).get(ATTR_CERT_SHA256)
        )
        presented = normalize_fingerprint(state.presented_sha256)
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            ids["certificate_changed"],
            is_fixable=True,
            severity=ir.IssueSeverity.WARNING,
            translation_key="certificate_changed",
            translation_placeholders={
                **placeholders,
                "fingerprint": format_fingerprint(stored) if stored else "",
                "new_fingerprint": format_fingerprint(presented) if presented else "",
            },
            data={
                "entry_id": self.config_entry.entry_id,
                "device_id": state.device_id,
                "fingerprint": stored,
                "new_fingerprint": presented,
            },
        )

    def payload(self) -> list[dict[str, Any]]:
        """Return the admin panel's view. No password is included."""
        rows: list[dict[str, Any]] = []
        data = self.data or {}
        for device_id, record in self.records.items():
            if record.get(ATTR_IGNORED):
                continue
            state = data.get(device_id)
            rows.append(
                {
                    "id": device_id,
                    "name": state.name if state else record.get("name"),
                    "host": state.host if state else record.get("host"),
                    "port": state.port if state else record.get("port"),
                    "scheme": state.scheme if state else record.get(CONF_SCHEME),
                    "url": state.admin_url if state else record_admin_url(record),
                    "model": state.model if state else record.get(ATTR_MODEL),
                    "board": state.board if state else record.get(ATTR_BOARD),
                    "firmware": state.firmware if state else record.get(ATTR_FIRMWARE),
                    "firmware_version": (
                        state.firmware_version
                        if state
                        else record.get(ATTR_FIRMWARE_VERSION)
                    ),
                    "project_name": (
                        state.project_name if state else record.get(ATTR_PROJECT_NAME)
                    ),
                    "online": bool(state and state.online),
                    "last_seen": state.last_seen.isoformat()
                    if state and state.last_seen
                    else None,
                    "web": bool(state.web) if state else bool(record.get(ATTR_WEB)),
                    "password_required": (
                        state.password_required
                        if state
                        else bool(record.get(ATTR_PASSWORD_REQUIRED))
                    ),
                    "credentials_set": bool(record.get(CONF_PASSWORD)),
                    "auth_failed": bool(state and state.auth_failed),
                    "mac": state.mac if state else record.get(ATTR_MAC),
                }
            )
        rows.sort(key=lambda row: str(row["name"] or "").lower())
        return rows


def _hint_from_record(record: dict[str, Any]) -> Candidate:
    """Return a candidate so a headless ESPHome node stays identified."""
    return Candidate(
        host=str(record["host"]),
        port=int(record.get("port") or DEFAULT_PORT),
        name=record.get("name"),
        mac=record.get(ATTR_MAC),
        node_name=record.get("node_name"),
        firmware=record.get(ATTR_FIRMWARE),
        firmware_version=record.get(ATTR_FIRMWARE_VERSION),
        esphome_version=record.get(ATTR_ESPHOME_VERSION),
        project_name=record.get(ATTR_PROJECT_NAME),
        project_version=record.get(ATTR_PROJECT_VERSION),
        git_repo=record.get(ATTR_GIT_REPO),
        model=record.get(ATTR_MODEL),
        board=record.get(ATTR_BOARD),
        api_port=record.get(ATTR_API_PORT),
        source=str(record.get("source") or "manual"),
    )


def _issue_id(kind: str, device_id: str) -> str:
    """Return a repair id. Issue ids are shown in logs, so keep them readable."""
    slug = device_id.replace(":", "_").replace("/", "_")
    return f"{kind}_{slug}"


@callback
def async_link_devices(hass: HomeAssistant, coordinator: RatgdoCoordinator) -> None:
    """Point our device at the ESPHome or HomeKit Controller device.

    Home Assistant 2026.10 keeps each device on one config entry, so a
    shared MAC no longer merges the rows by itself. The MAC connection is
    still stored (see the entity device info) for installs that do merge,
    and ``via_device_id`` is written only on our device. ESPHome firmware
    prefers the ESPHome row; HomeKit firmware prefers HomeKit Controller.
    """
    registry = dr.async_get(hass)
    entry_id = coordinator.config_entry.entry_id
    for state in (coordinator.data or {}).values():
        ours = registry.async_get_device_by_identifier(
            (DOMAIN, state.device_id), entry_id
        )
        if ours is None:
            continue
        other = _linked_device(hass, registry, state)
        if other is None or other.id == ours.id:
            continue
        if ours.via_device_id != other.id:
            registry.async_update_device(ours.id, via_device_id=other.id)


def _linked_device(
    hass: HomeAssistant,
    registry: dr.DeviceRegistry,
    state: DeviceRuntime,
) -> dr.DeviceEntry | None:
    """Return the existing integration's device for this controller."""
    primary = ESPHOME_DOMAIN if state.firmware == FIRMWARE_ESPHOME else HOMEKIT_DOMAIN
    secondary = HOMEKIT_DOMAIN if primary == ESPHOME_DOMAIN else ESPHOME_DOMAIN
    found = _device_in_domain(hass, registry, state, primary)
    if found is not None:
        return found
    return _device_in_domain(hass, registry, state, secondary)


def _device_in_domain(
    hass: HomeAssistant,
    registry: dr.DeviceRegistry,
    state: DeviceRuntime,
    domain: str,
) -> dr.DeviceEntry | None:
    """Return a device in ``domain`` with this MAC, or the only name match."""
    connection = (dr.CONNECTION_NETWORK_MAC, state.mac) if state.mac else None
    named: list[dr.DeviceEntry] = []
    for entry in hass.config_entries.async_entries(domain):
        if connection is not None:
            device = registry.async_get_device_by_connection(connection, entry.entry_id)
            if device is not None:
                return device
        named.extend(
            device
            for device in dr.async_entries_for_config_entry(registry, entry.entry_id)
            if device.name == state.name
        )
    if len(named) == 1:
        return named[0]
    return None
