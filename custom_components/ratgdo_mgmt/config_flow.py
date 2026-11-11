"""Config flow for ratgdo Mgmt.

One config entry manages every controller. Zeroconf, DHCP, and HomeKit
discovery start that entry the first time a ratgdo is seen. After that
each new advertisement is probed and added to the same entry. Adding a
controller by host is the user step before the entry exists, and an
options step after it does.

A saved web password is optional. HomeKit ``/status.json`` does not need
one. The password is what the proxy sends as ``X-API-Key`` so the
embedded settings page does not have to ask again, and what an ESPHome
``web_server`` auth block expects.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import logging
from typing import Any

import probatio

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .client import ProbeResult, async_probe
from .const import (
    ATTR_CERT_SHA256,
    CONF_DEVICE_ID,
    CONF_PASSWORD,
    CONF_SCHEME,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DOMAIN,
    SCHEME_AUTO,
    SCHEME_HTTPS,
    SCHEMES,
)
from .discovery import Candidate, candidate_from_dhcp, parse_zeroconf
from .records import apply_candidate, credentials_for, devices_from_options, without
from .tls import format_fingerprint, normalize_fingerprint

_LOGGER = logging.getLogger(__name__)


def _connection_schema(defaults: Mapping[str, Any]) -> probatio.Schema:
    """Schema for host, port, protocol, certificate checking, and web auth."""
    return probatio.Schema(
        {
            probatio.Required(
                CONF_HOST, default=defaults.get(CONF_HOST, "")
            ): TextSelector(),
            probatio.Required(
                CONF_PORT, default=int(defaults.get(CONF_PORT, DEFAULT_PORT))
            ): NumberSelector(
                NumberSelectorConfig(
                    min=1,
                    max=65535,
                    mode=NumberSelectorMode.BOX,
                    step=1,
                )
            ),
            probatio.Required(
                CONF_SCHEME, default=defaults.get(CONF_SCHEME, SCHEME_AUTO)
            ): SelectSelector(
                SelectSelectorConfig(
                    options=list(SCHEMES),
                    translation_key="scheme",
                    mode=SelectSelectorMode.DROPDOWN,
                )
            ),
            probatio.Required(
                CONF_VERIFY_SSL, default=bool(defaults.get(CONF_VERIFY_SSL, False))
            ): BooleanSelector(),
            probatio.Optional(
                CONF_USERNAME, default=defaults.get(CONF_USERNAME) or ""
            ): TextSelector(),
            probatio.Optional(CONF_PASSWORD, default=""): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
        }
    )


def _clean_connection(user_input: dict[str, Any]) -> dict[str, Any] | str:
    """Return a cleaned connection, or an error key."""
    host = str(user_input.get(CONF_HOST, "")).strip().rstrip(".")
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip("[]")
    if not host or any(char.isspace() for char in host):
        return "invalid_host"
    try:
        port = int(user_input[CONF_PORT])
    except KeyError, TypeError, ValueError:
        return "invalid_host"
    if port < 1 or port > 65535:
        return "invalid_host"
    scheme = str(user_input.get(CONF_SCHEME, SCHEME_AUTO))
    if scheme not in SCHEMES:
        return "invalid_host"
    username = str(user_input.get(CONF_USERNAME) or "").strip()
    password = str(user_input.get(CONF_PASSWORD) or "")
    return {
        CONF_HOST: host,
        CONF_PORT: port,
        CONF_SCHEME: scheme,
        CONF_VERIFY_SSL: bool(user_input.get(CONF_VERIFY_SSL, False)),
        CONF_USERNAME: username or None,
        CONF_PASSWORD: password or None,
    }


def _device_options(records: Mapping[str, Mapping[str, Any]]) -> list[SelectOptionDict]:
    """Return selector options for the stored controllers."""
    options: list[SelectOptionDict] = []
    for device_id, record in sorted(
        records.items(), key=lambda item: str(item[1].get("name") or "").lower()
    ):
        name = str(record.get("name") or record.get("host"))
        if record.get("ignored"):
            name = f"{name} (ignored)"
        options.append({"value": device_id, "label": name})
    return options


@dataclass
class _Pending:
    """A connection the user has not finished accepting."""

    cleaned: dict[str, Any]
    probe: ProbeResult
    fingerprint: str
    old_fingerprint: str | None
    device_id: str | None
    base: dict[str, dict[str, Any]]
    source: str
    preserved: Mapping[str, Any]


def _note(fingerprint: str | None) -> str:
    """Return the sentence appended to a connection form, or empty."""
    normalized = normalize_fingerprint(fingerprint)
    if normalized is None:
        return ""
    return (
        f"SHA-256: {format_fingerprint(normalized)}. "
        "Leave Verify SSL certificate off to pin this certificate."
    )


def _classify(
    cleaned: Mapping[str, Any],
    probe: ProbeResult,
    stored: str | None,
) -> str:
    """Return pin, accept, save, ssl_error, or cannot_connect."""
    presented = normalize_fingerprint(probe.cert_sha256)
    if probe.cert_mismatch and presented:
        return "accept"
    if not probe.ok:
        return "ssl_error" if probe.ssl_error else "cannot_connect"
    if cleaned.get(CONF_VERIFY_SSL) or probe.scheme != SCHEME_HTTPS:
        return "save"
    previous = normalize_fingerprint(stored)
    if presented and presented != previous:
        return "pin" if previous is None else "accept"
    return "save"


def _records_for(
    cleaned: Mapping[str, Any],
    probe: ProbeResult,
    base: Mapping[str, Mapping[str, Any]],
    *,
    device_id: str | None,
    source: str,
    preserved: Mapping[str, Any],
    fingerprint: str | None,
) -> dict[str, dict[str, Any]]:
    """Merge a probed connection, including a fingerprint the user accepted."""
    accepted = probe
    if not probe.ok:
        accepted = ProbeResult(
            ok=True,
            scheme=probe.scheme or SCHEME_HTTPS,
            ssl_error=False,
            cert_sha256=fingerprint,
            firmware=probe.firmware,
            name=probe.name or _text(preserved.get("name")),
            firmware_version=probe.firmware_version,
            model=probe.model,
            board=probe.board,
            mac=probe.mac,
            web=probe.web,
        )
    password = cleaned.get(CONF_PASSWORD)
    if password is None:
        password = preserved.get(CONF_PASSWORD)
    username = cleaned.get(CONF_USERNAME)
    if username is None:
        username = preserved.get(CONF_USERNAME)
    candidate = Candidate(
        host=str(cleaned[CONF_HOST]),
        port=int(cleaned[CONF_PORT]),
        scheme_mode=str(cleaned[CONF_SCHEME]),
        name=accepted.name or _text(preserved.get("name")),
        mac=accepted.mac or _text(preserved.get("mac")),
        node_name=_text(preserved.get("node_name")),
        firmware=accepted.firmware,
        firmware_version=accepted.firmware_version,
        project_name=accepted.project_name or _text(preserved.get("project_name")),
        project_version=accepted.project_version,
        git_repo=accepted.git_repo or _text(preserved.get("git_repo")),
        model=accepted.model or _text(preserved.get("model")),
        board=accepted.board or _text(preserved.get("board")),
        web_port_known=True,
        source=source,
    )
    return apply_candidate(
        base,
        candidate,
        accepted,
        verify_ssl=bool(cleaned.get(CONF_VERIFY_SSL)),
        scheme_mode=str(cleaned[CONF_SCHEME]),
        device_id=device_id,
        cert_sha256=None if cleaned.get(CONF_VERIFY_SSL) else fingerprint,
        username=username if isinstance(username, str) else None,
        password=password if isinstance(password, str) else None,
    )


def _text(value: Any) -> str | None:
    """Return a stripped string, or None."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


class _CertificateSteps:
    """Pin and accept steps shared by the config flow and the options flow."""

    _pending: _Pending | None
    _seen_fingerprint: str | None
    _last_probe: ProbeResult

    async def _async_offer(
        self,
        cleaned: dict[str, Any],
        base: dict[str, dict[str, Any]],
        *,
        device_id: str | None,
        source: str,
        preserved: Mapping[str, Any],
        stored: str | None,
        hint: Candidate | None = None,
    ) -> ConfigFlowResult | str | None:
        """Probe and either return a form, an error key, or None to save now."""
        username = cleaned.get(CONF_USERNAME) or preserved.get(CONF_USERNAME)
        password = cleaned.get(CONF_PASSWORD)
        if not password:
            _user, password = credentials_for(preserved) if preserved else (None, None)
        probe = await async_probe(
            self.hass,
            cleaned[CONF_HOST],
            cleaned[CONF_PORT],
            cleaned[CONF_SCHEME],
            cleaned[CONF_VERIFY_SSL],
            pinned_sha256=None if cleaned[CONF_VERIFY_SSL] else stored,
            hint=hint,
            username=username if isinstance(username, str) else None,
            password=password if isinstance(password, str) else None,
        )
        self._last_probe = probe
        action = _classify(cleaned, probe, stored)
        if action in ("ssl_error", "cannot_connect"):
            self._seen_fingerprint = probe.cert_sha256
            return action
        if action in ("pin", "accept"):
            fingerprint = normalize_fingerprint(probe.cert_sha256) or ""
            self._pending = _Pending(
                cleaned=cleaned,
                probe=probe,
                fingerprint=fingerprint,
                old_fingerprint=normalize_fingerprint(stored),
                device_id=device_id,
                base=base,
                source=source,
                preserved=preserved,
            )
            if action == "pin":
                return await self.async_step_pin_certificate()
            return await self.async_step_accept_certificate()
        return None

    async def async_step_pin_certificate(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the leaf fingerprint and store it when the user submits."""
        return await self._async_certificate_form("pin_certificate", user_input)

    async def async_step_accept_certificate(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the old and new fingerprints and replace the pin on submit."""
        return await self._async_certificate_form("accept_certificate", user_input)

    async def _async_certificate_form(
        self, step_id: str, user_input: dict[str, Any] | None
    ) -> ConfigFlowResult:
        """Render one certificate step."""
        pending = self._pending
        if pending is None:
            return self.async_abort(reason="cannot_connect")
        if user_input is not None:
            return await self._apply_pending(pending)
        name = pending.probe.name or _text(pending.preserved.get("name"))
        return self.async_show_form(
            step_id=step_id,
            data_schema=probatio.Schema({}),
            description_placeholders={
                "name": name or str(pending.cleaned[CONF_HOST]),
                "host": str(pending.cleaned[CONF_HOST]),
                "fingerprint": format_fingerprint(pending.fingerprint),
                "old_fingerprint": format_fingerprint(pending.old_fingerprint)
                if pending.old_fingerprint
                else "",
            },
        )

    async def _apply_pending(self, pending: _Pending) -> ConfigFlowResult:
        """Store the accepted connection. Subclasses decide how the entry updates."""
        raise NotImplementedError


class RatgdoMgmtConfigFlow(_CertificateSteps, ConfigFlow, domain=DOMAIN):
    """Set up the one ratgdo Mgmt entry."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        """Remember the advertisement waiting for confirmation."""
        self._candidate: Candidate | None = None
        self._reconfigure_id: str | None = None
        self._pending = None
        self._seen_fingerprint = None
        self._last_probe = ProbeResult(ok=False, scheme=None, ssl_error=False)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Add the entry by typing the first controller's host."""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        return await self._async_connection_step("user", user_input, create=True)

    async def async_step_zeroconf(
        self, discovery_info: ZeroconfServiceInfo
    ) -> ConfigFlowResult:
        """Start from an advertisement, or add to the entry that already exists."""
        return await self._async_discovery(parse_zeroconf(discovery_info))

    async def async_step_homekit(
        self, discovery_info: ZeroconfServiceInfo
    ) -> ConfigFlowResult:
        """Start from a HomeKit accessory whose model is a ratgdo."""
        return await self._async_discovery(parse_zeroconf(discovery_info))

    async def async_step_dhcp(
        self, discovery_info: DhcpServiceInfo
    ) -> ConfigFlowResult:
        """Start from a DHCP hostname the stock firmware uses."""
        return await self._async_discovery(candidate_from_dhcp(discovery_info))

    async def _async_discovery(self, candidate: Candidate | None) -> ConfigFlowResult:
        """Confirm a discovered controller, or fold it into the existing entry."""
        if candidate is None:
            return self.async_abort(reason="not_ratgdo")
        await self.async_set_unique_id(DOMAIN)
        if entries := self._async_current_entries():
            adopted = await _adopt_into_entry(self.hass, entries[0], candidate)
            if not adopted:
                _LOGGER.debug(
                    "Ignoring %s:%s until it answers as a ratgdo",
                    candidate.host,
                    candidate.port,
                )
            return self.async_abort(reason="already_configured")
        probe = await async_probe(
            self.hass,
            candidate.host,
            candidate.port,
            candidate.scheme_mode,
            verify_ssl=False,
            hint=candidate,
        )
        if not probe.ok:
            return self.async_abort(reason="cannot_connect")
        self._candidate = candidate
        self._last_probe = probe
        self._seen_fingerprint = probe.cert_sha256
        self.context["title_placeholders"] = {
            "name": probe.name or candidate.name or candidate.host
        }
        return await self.async_step_confirm()

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm the discovered controller and create the single entry."""
        candidate = self._candidate
        probe = self._last_probe
        if candidate is None or not probe.ok:
            return self.async_abort(reason="cannot_connect")
        if user_input is None:
            return self.async_show_form(
                step_id="confirm",
                description_placeholders={
                    "name": probe.name or candidate.name or candidate.host,
                    "host": candidate.host,
                    "firmware": probe.firmware or candidate.firmware or "unknown",
                    "model": probe.model or candidate.model or "unknown",
                    "fingerprint": _note(self._seen_fingerprint),
                },
            )
        fresh = await async_probe(
            self.hass,
            candidate.host,
            candidate.port,
            candidate.scheme_mode,
            verify_ssl=False,
            hint=candidate,
        )
        if not fresh.ok:
            return self.async_abort(reason="cannot_connect")
        records = apply_candidate(
            {},
            candidate,
            fresh,
            verify_ssl=False,
            cert_sha256=fresh.cert_sha256,
        )
        return self.async_create_entry(
            title="ratgdo Mgmt",
            data={},
            options={"devices": records},
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose which controller's address to edit."""
        entry = self._get_reconfigure_entry()
        records = devices_from_options(entry.options)
        if not records:
            return self.async_abort(reason="no_devices")
        if len(records) == 1 and user_input is None:
            self._reconfigure_id = next(iter(records))
            return await self.async_step_reconfigure_connection()
        if user_input is not None:
            self._reconfigure_id = str(user_input[CONF_DEVICE_ID])
            return await self.async_step_reconfigure_connection()
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=probatio.Schema(
                {
                    probatio.Required(CONF_DEVICE_ID): SelectSelector(
                        SelectSelectorConfig(
                            options=_device_options(records),
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
        )

    async def async_step_reconfigure_connection(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit one controller's host, port, protocol, and certificate check."""
        entry = self._get_reconfigure_entry()
        records = devices_from_options(entry.options)
        device_id = self._reconfigure_id
        if device_id is None or device_id not in records:
            return self.async_abort(reason="no_devices")
        record = records[device_id]
        errors: dict[str, str] = {}
        if user_input is not None:
            cleaned = _clean_connection(user_input)
            if isinstance(cleaned, str):
                errors["base"] = cleaned
            else:
                outcome = await self._async_offer(
                    cleaned,
                    records,
                    device_id=device_id,
                    source="reconfigure",
                    preserved=record,
                    stored=record.get(ATTR_CERT_SHA256),
                    hint=_hint(record),
                )
                if isinstance(outcome, str):
                    errors["base"] = outcome
                elif outcome is not None:
                    return outcome
                updated = _records_for(
                    cleaned,
                    self._last_probe,
                    records,
                    device_id=device_id,
                    source="reconfigure",
                    preserved=record,
                    fingerprint=None
                    if cleaned[CONF_VERIFY_SSL]
                    else self._last_probe.cert_sha256,
                )
                return self.async_update_reload_and_abort(
                    entry,
                    options={"devices": updated},
                )
        return self.async_show_form(
            step_id="reconfigure_connection",
            data_schema=_connection_schema(_defaults(record)),
            errors=errors or None,
            description_placeholders={
                "name": str(record.get("name") or record.get("host")),
                "fingerprint": _note(self._seen_fingerprint),
            },
        )

    async def _async_connection_step(
        self,
        step_id: str,
        user_input: dict[str, Any] | None,
        *,
        create: bool,
    ) -> ConfigFlowResult:
        """Show the manual-add form and create the entry when the probe works."""
        errors: dict[str, str] = {}
        if user_input is not None:
            cleaned = _clean_connection(user_input)
            if isinstance(cleaned, str):
                errors["base"] = cleaned
            else:
                outcome = await self._async_offer(
                    cleaned,
                    {},
                    device_id=None,
                    source="manual",
                    preserved={},
                    stored=None,
                )
                if isinstance(outcome, str):
                    errors["base"] = outcome
                elif outcome is not None:
                    return outcome
                elif create:
                    records = _records_for(
                        cleaned,
                        self._last_probe,
                        {},
                        device_id=None,
                        source="manual",
                        preserved={},
                        fingerprint=None
                        if cleaned[CONF_VERIFY_SSL]
                        else self._last_probe.cert_sha256,
                    )
                    await self.async_set_unique_id(DOMAIN)
                    return self.async_create_entry(
                        title="ratgdo Mgmt",
                        data={},
                        options={"devices": records},
                    )
        return self.async_show_form(
            step_id=step_id,
            data_schema=_connection_schema({}),
            errors=errors or None,
            description_placeholders={"fingerprint": _note(self._seen_fingerprint)},
        )

    async def _apply_pending(self, pending: _Pending) -> ConfigFlowResult:
        """Create the entry, or save a reconfigured controller."""
        updated = _records_for(
            pending.cleaned,
            pending.probe,
            pending.base,
            device_id=pending.device_id,
            source=pending.source,
            preserved=pending.preserved,
            fingerprint=pending.fingerprint,
        )
        if pending.source == "reconfigure":
            return self.async_update_reload_and_abort(
                self._get_reconfigure_entry(),
                options={"devices": updated},
            )
        await self.async_set_unique_id(DOMAIN)
        return self.async_create_entry(
            title="ratgdo Mgmt",
            data={},
            options={"devices": updated},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> RatgdoMgmtOptionsFlow:
        """Return the options flow."""
        return RatgdoMgmtOptionsFlow()


class RatgdoMgmtOptionsFlow(_CertificateSteps, OptionsFlowWithReload):
    """Add, edit, ignore, and remove controllers on the single entry."""

    def __init__(self) -> None:
        """Remember which controller the manage steps are about."""
        self._device_id: str | None = None
        self._pending = None
        self._seen_fingerprint = None
        self._last_probe = ProbeResult(ok=False, scheme=None, ssl_error=False)

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose add or manage."""
        return self.async_show_menu(step_id="init", menu_options=["add", "manage"])

    async def async_step_add(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Add a controller by host."""
        errors: dict[str, str] = {}
        if user_input is not None:
            cleaned = _clean_connection(user_input)
            if isinstance(cleaned, str):
                errors["base"] = cleaned
            else:
                records = devices_from_options(self.config_entry.options)
                outcome = await self._async_offer(
                    cleaned,
                    records,
                    device_id=None,
                    source="manual",
                    preserved={},
                    stored=None,
                )
                if isinstance(outcome, str):
                    errors["base"] = outcome
                elif outcome is not None:
                    return outcome
                updated = _records_for(
                    cleaned,
                    self._last_probe,
                    records,
                    device_id=None,
                    source="manual",
                    preserved={},
                    fingerprint=None
                    if cleaned[CONF_VERIFY_SSL]
                    else self._last_probe.cert_sha256,
                )
                if updated == records:
                    errors["base"] = "already_tracked"
                else:
                    return self.async_create_entry(data={"devices": updated})
        return self.async_show_form(
            step_id="add",
            data_schema=_connection_schema({}),
            errors=errors or None,
            description_placeholders={"fingerprint": _note(self._seen_fingerprint)},
        )

    async def _apply_pending(self, pending: _Pending) -> ConfigFlowResult:
        """Save a controller added or edited from the options flow."""
        updated = _records_for(
            pending.cleaned,
            pending.probe,
            pending.base,
            device_id=pending.device_id,
            source=pending.source,
            preserved=pending.preserved,
            fingerprint=pending.fingerprint,
        )
        return self.async_create_entry(data={"devices": updated})

    async def async_step_manage(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick a controller to edit, ignore, or remove."""
        records = devices_from_options(self.config_entry.options)
        if not records:
            return self.async_abort(reason="no_devices")
        if user_input is not None:
            self._device_id = str(user_input[CONF_DEVICE_ID])
            return await self.async_step_device()
        return self.async_show_form(
            step_id="manage",
            data_schema=probatio.Schema(
                {
                    probatio.Required(CONF_DEVICE_ID): SelectSelector(
                        SelectSelectorConfig(
                            options=_device_options(records),
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
        )

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Choose what to do with the selected controller."""
        records = devices_from_options(self.config_entry.options)
        record = records.get(self._device_id or "")
        if record is None:
            return self.async_abort(reason="no_devices")
        include = "include" if record.get("ignored") else "ignore"
        return self.async_show_menu(
            step_id="device",
            menu_options=["edit", include, "remove"],
            description_placeholders={
                "name": str(record.get("name") or record.get("host"))
            },
        )

    async def async_step_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change one controller's connection."""
        records = devices_from_options(self.config_entry.options)
        device_id = self._device_id
        if device_id is None or device_id not in records:
            return self.async_abort(reason="no_devices")
        record = records[device_id]
        errors: dict[str, str] = {}
        if user_input is not None:
            cleaned = _clean_connection(user_input)
            if isinstance(cleaned, str):
                errors["base"] = cleaned
            else:
                outcome = await self._async_offer(
                    cleaned,
                    records,
                    device_id=device_id,
                    source="options",
                    preserved=record,
                    stored=record.get(ATTR_CERT_SHA256),
                    hint=_hint(record),
                )
                if isinstance(outcome, str):
                    errors["base"] = outcome
                elif outcome is not None:
                    return outcome
                updated = _records_for(
                    cleaned,
                    self._last_probe,
                    records,
                    device_id=device_id,
                    source="options",
                    preserved=record,
                    fingerprint=None
                    if cleaned[CONF_VERIFY_SSL]
                    else self._last_probe.cert_sha256,
                )
                return self.async_create_entry(data={"devices": updated})
        return self.async_show_form(
            step_id="edit",
            data_schema=_connection_schema(_defaults(record)),
            errors=errors or None,
            description_placeholders={
                "name": str(record.get("name") or record.get("host")),
                "fingerprint": _note(self._seen_fingerprint),
            },
        )

    async def async_step_ignore(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Stop managing a controller without forgetting it should stay hidden."""
        return await self._async_flag_step("ignore", user_input, ignored=True)

    async def async_step_include(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage an ignored controller again."""
        return await self._async_flag_step("include", user_input, ignored=False)

    async def async_step_remove(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Remove a controller. A later discovery can add it again."""
        records = devices_from_options(self.config_entry.options)
        record = records.get(self._device_id or "")
        if record is None or self._device_id is None:
            return self.async_abort(reason="no_devices")
        if user_input is not None:
            return self.async_create_entry(
                data={"devices": without(records, self._device_id)}
            )
        return self.async_show_form(
            step_id="remove",
            data_schema=probatio.Schema({}),
            description_placeholders={
                "name": str(record.get("name") or record.get("host"))
            },
        )

    async def _async_flag_step(
        self,
        step_id: str,
        user_input: dict[str, Any] | None,
        *,
        ignored: bool,
    ) -> ConfigFlowResult:
        """Confirm ignoring or including a controller."""
        records = devices_from_options(self.config_entry.options)
        record = records.get(self._device_id or "")
        if record is None or self._device_id is None:
            return self.async_abort(reason="no_devices")
        if user_input is not None:
            records[self._device_id]["ignored"] = ignored
            return self.async_create_entry(data={"devices": records})
        return self.async_show_form(
            step_id=step_id,
            data_schema=probatio.Schema({}),
            description_placeholders={
                "name": str(record.get("name") or record.get("host"))
            },
        )


def _defaults(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return form defaults. The password is not echoed back."""
    return {
        CONF_HOST: record.get("host", ""),
        CONF_PORT: record.get("port", DEFAULT_PORT),
        CONF_SCHEME: record.get("scheme_mode", SCHEME_AUTO),
        CONF_VERIFY_SSL: record.get("verify_ssl", False),
        CONF_USERNAME: record.get(CONF_USERNAME) or record.get("www_username") or "",
    }


def _hint(record: Mapping[str, Any]) -> Candidate:
    """Return a hint so editing a headless ESPHome node still probes as one."""
    return Candidate(
        host=str(record.get("host") or ""),
        port=int(record.get("port") or DEFAULT_PORT),
        name=_text(record.get("name")),
        mac=_text(record.get("mac")),
        firmware=_text(record.get("firmware")),
        project_name=_text(record.get("project_name")),
        project_version=_text(record.get("project_version")),
        git_repo=_text(record.get("git_repo")),
        model=_text(record.get("model")),
        board=_text(record.get("board")),
        source="manual",
    )


async def _adopt_into_entry(
    hass: Any, entry: ConfigEntry, candidate: Candidate
) -> bool:
    """Probe and store a candidate on an entry that is already set up."""
    coordinator = getattr(entry, "runtime_data", None)
    if coordinator is not None:
        return await coordinator.async_adopt(candidate)
    result = await async_probe(
        hass,
        candidate.host,
        candidate.port,
        candidate.scheme_mode,
        False,
        hint=candidate,
    )
    merged = apply_candidate(devices_from_options(entry.options), candidate, result)
    current = devices_from_options(entry.options)
    if merged == current:
        return False
    hass.config_entries.async_update_entry(entry, options={"devices": merged})
    return True
