"""Repairs for a changed certificate or a rejected web password.

The coordinator raises ``certificate_changed`` when a stored SHA-256 does
not match the leaf, and ``auth_failed`` when a saved password is rejected
by ``GET /auth`` (HomeKit firmware returns 403 for a bad ``X-API-Key``).
Submitting stores the new fingerprint or the new password and probes again.
"""

from __future__ import annotations

from typing import Any

import probatio

from homeassistant.components.repairs import RepairsFlow, RepairsFlowResult
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .client import async_probe
from .const import (
    ATTR_CERT_SHA256,
    ATTR_SCHEME_MODE,
    CONF_PASSWORD,
    CONF_SCHEME,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DOMAIN,
    SCHEME_AUTO,
)
from .coordinator import RatgdoCoordinator
from .discovery import Candidate
from .records import devices_from_options
from .tls import format_fingerprint, normalize_fingerprint


class CertificateChangedFlow(RepairsFlow):
    """Ask the user to accept a new leaf certificate."""

    def __init__(self, entry_id: str, device_id: str) -> None:
        """Remember which controller the issue is about."""
        self._entry_id = entry_id
        self._device_id = device_id
        self._presented: str | None = None

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> RepairsFlowResult:
        """Show the stored and presented fingerprints, then store the new one."""
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if entry is None:
            return self.async_abort(reason="cannot_connect")
        records = devices_from_options(entry.options)
        record = records.get(self._device_id)
        if record is None:
            return self.async_abort(reason="cannot_connect")
        if user_input is not None and "issue_id" not in user_input:
            return await self._async_accept(entry, records, record)
        probe = await async_probe(
            self.hass,
            str(record["host"]),
            int(record.get("port") or DEFAULT_PORT),
            str(record.get(ATTR_SCHEME_MODE) or SCHEME_AUTO),
            bool(record.get(CONF_VERIFY_SSL)),
            preferred=str(record.get(CONF_SCHEME) or "") or None,
            pinned_sha256=record.get(ATTR_CERT_SHA256),
            hint=_hint(record),
        )
        if probe.ok or not probe.cert_mismatch:
            return self.async_create_entry(title="", data={})
        self._presented = normalize_fingerprint(probe.cert_sha256)
        stored = normalize_fingerprint(record.get(ATTR_CERT_SHA256))
        return self.async_show_form(
            step_id="init",
            data_schema=probatio.Schema({}),
            description_placeholders={
                "name": str(record.get("name") or record.get("host")),
                "host": str(record.get("host")),
                "fingerprint": format_fingerprint(stored) if stored else "",
                "new_fingerprint": format_fingerprint(self._presented)
                if self._presented
                else "",
            },
        )

    async def _async_accept(
        self,
        entry: Any,
        records: dict[str, dict[str, Any]],
        record: dict[str, Any],
    ) -> RepairsFlowResult:
        """Store the fingerprint the controller just presented and probe again."""
        presented = self._presented
        if presented is None:
            probe = await async_probe(
                self.hass,
                str(record["host"]),
                int(record.get("port") or DEFAULT_PORT),
                str(record.get(ATTR_SCHEME_MODE) or SCHEME_AUTO),
                False,
                hint=_hint(record),
            )
            presented = normalize_fingerprint(probe.cert_sha256)
        if presented is None:
            return self.async_abort(reason="cannot_connect")
        records[self._device_id][ATTR_CERT_SHA256] = presented
        records[self._device_id][CONF_VERIFY_SSL] = False
        self.hass.config_entries.async_update_entry(entry, options={"devices": records})
        runtime = getattr(entry, "runtime_data", None)
        if isinstance(runtime, RatgdoCoordinator):
            runtime.records = records
            await runtime.async_refresh()
            state = (runtime.data or {}).get(self._device_id)
            if state is not None and state.cert_mismatch:
                return self.async_abort(reason="cannot_connect")
        ir.async_delete_issue(
            self.hass, DOMAIN, f"certificate_changed_{_slug(self._device_id)}"
        )
        return self.async_create_entry(title="", data={})


class AuthFailedFlow(RepairsFlow):
    """Replace a web password the controller rejected."""

    def __init__(self, entry_id: str, device_id: str) -> None:
        """Remember which controller the issue is about."""
        self._entry_id = entry_id
        self._device_id = device_id

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> RepairsFlowResult:
        """Ask for the username and password, then probe ``/auth`` again."""
        entry = self.hass.config_entries.async_get_entry(self._entry_id)
        if entry is None:
            return self.async_abort(reason="cannot_connect")
        records = devices_from_options(entry.options)
        record = records.get(self._device_id)
        if record is None:
            return self.async_abort(reason="cannot_connect")
        errors: dict[str, str] = {}
        if user_input is not None and "issue_id" not in user_input:
            username = str(user_input.get(CONF_USERNAME) or "").strip()
            password = str(user_input.get(CONF_PASSWORD) or "")
            if not password:
                errors["base"] = "invalid_auth"
            else:
                records[self._device_id][CONF_USERNAME] = username or None
                records[self._device_id][CONF_PASSWORD] = password
                self.hass.config_entries.async_update_entry(
                    entry, options={"devices": records}
                )
                runtime = getattr(entry, "runtime_data", None)
                if isinstance(runtime, RatgdoCoordinator):
                    runtime.records = records
                    await runtime.async_refresh()
                    state = (runtime.data or {}).get(self._device_id)
                    if state is not None and state.auth_failed:
                        return self.async_abort(reason="invalid_auth")
                ir.async_delete_issue(
                    self.hass, DOMAIN, f"auth_failed_{_slug(self._device_id)}"
                )
                return self.async_create_entry(title="", data={})
        return self.async_show_form(
            step_id="init",
            data_schema=probatio.Schema(
                {
                    probatio.Optional(
                        CONF_USERNAME,
                        default=record.get(CONF_USERNAME)
                        or record.get("www_username")
                        or "admin",
                    ): TextSelector(),
                    probatio.Required(CONF_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD)
                    ),
                }
            ),
            errors=errors or None,
            description_placeholders={
                "name": str(record.get("name") or record.get("host")),
            },
        )


def _hint(record: dict[str, Any]) -> Candidate:
    """Return a probe hint from a stored record."""
    return Candidate(
        host=str(record.get("host") or ""),
        port=int(record.get("port") or DEFAULT_PORT),
        firmware=record.get("firmware")
        if isinstance(record.get("firmware"), str)
        else None,
        project_name=record.get("project_name")
        if isinstance(record.get("project_name"), str)
        else None,
        mac=record.get("mac") if isinstance(record.get("mac"), str) else None,
    )


def _slug(device_id: str) -> str:
    """Match the issue id the coordinator builds."""
    return device_id.replace(":", "_").replace("/", "_")


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, str | int | float | None] | None,
) -> RepairsFlow:
    """Start the certificate or password repair."""
    from homeassistant.components.repairs import ConfirmRepairFlow

    if data and issue_id.startswith("certificate_changed_"):
        entry_id = data.get("entry_id")
        device_id = data.get("device_id")
        if isinstance(entry_id, str) and isinstance(device_id, str):
            return CertificateChangedFlow(entry_id, device_id)
    if data and issue_id.startswith("auth_failed_"):
        entry_id = data.get("entry_id")
        device_id = data.get("device_id")
        if isinstance(entry_id, str) and isinstance(device_id, str):
            return AuthFailedFlow(entry_id, device_id)
    return ConfirmRepairFlow()
