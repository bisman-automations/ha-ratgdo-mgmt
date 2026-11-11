"""Probe a ratgdo web port and run the few HTTP actions the firmware documents.

Identity, in the order the probe tries them:

- ``GET /status.json`` is the HomeKit firmware's unauthenticated status
  document (``web.cpp`` ``handle_status`` / ``build_status_json``). A
  document is one of ours when ``gitRepo`` is ``homekit-ratgdo`` or
  ``homekit-ratgdo32`` and ``firmwareVersion`` is a non-empty string.
  Those two keys are always written. The sample ``src/www/status.json``
  in the firmware tree is a fixture and is missing ``gitRepo``; the
  running firmware is not.
- ``GET /`` is the ESPHome ``web_server`` UI (``web_server.cpp``
  ``handle_index_request``). Versions 2 and 3 serve a small HTML page
  that loads ``https://oi.esphome.io/v2/www.js`` or ``v3/www.js``, unless
  ``local: true`` embeds that script (gzip, ``USE_WEBSERVER_LOCAL``).
  ``/0.js`` exists only when ``js_include`` is set. A 401 whose
  ``WWW-Authenticate`` scheme is Basic or Digest means the page is there
  and ``auth:`` is on (Basic is the 2026.10 default). A build that
  removes ``web_server`` does not answer. An ESPHome node is still
  accepted when mDNS already said ``project_name`` starts with
  ``ratgdo.``: the native API on 6053 is not HTTP, and this integration
  does not speak it (that would duplicate the ESPHome integration).
- ``GET /auth`` with ``X-API-Key`` checks a saved HomeKit password.
  200 means the hash matched. 403 means it did not (``requestAuthenticated``
  sends 403 for a bad key, 401 only when the header is absent).

``POST /reboot`` is intentionally unauthenticated in ``handle_reboot``.
ESPHome's stock Restart button is a ``button`` entity named ``Restart``.
Since the 2026.x web server, the action URL is the entity name from the
``/events`` list (``POST /button/Restart/press``), not the older object
id ``/button/restart/press``. ``handle_button_request`` still accepts
``press``.

Scheme ``auto`` tries HTTP first, then HTTPS. These devices ship on HTTP.
HTTPS uses the same three outcomes as a pinned admin page: authority
check, stored fingerprint, or a one-time observation of the leaf.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import logging
import ssl
from typing import Any
from urllib.parse import quote, urlsplit

import aiohttp
from aiohttp import ClientError, ClientResponse, ClientTimeout
from aiohttp.client_exceptions import ServerFingerprintMismatch
from aiohttp.hdrs import AUTHORIZATION

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .auth import api_key, authorization_for_challenge, basic_authorization
from .const import (
    AUTH_PATH,
    DEFAULT_PORT,
    DEFAULT_USERNAME,
    ESPHOME_JS_PATH,
    FIRMWARE_ESPHOME,
    FIRMWARE_HOMEKIT,
    HOMEKIT_REPOS,
    PROBE_TIMEOUT,
    REBOOT_PATH,
    SCHEME_AUTO,
    SCHEME_HTTP,
    SCHEME_HTTPS,
    STATUS_PATH,
)
from .discovery import Candidate, classify_board, normalize_mac
from .tls import (
    fingerprint_sha256,
    normalize_fingerprint,
    peer_fingerprint,
    pinned_ssl,
    unverified_context,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ProbeResult:
    """What one pass over the web port found.

    ``ok`` means this is a ratgdo we can manage. ``web`` means its own
    page answered, which the HomeKit firmware always has and ESPHome has
    only when ``web_server`` is compiled in. ``auth_failed`` means a saved
    password was rejected. The device is still online in that case.
    """

    ok: bool
    scheme: str | None
    ssl_error: bool
    firmware: str | None = None
    name: str | None = None
    firmware_version: str | None = None
    esphome_version: str | None = None
    project_name: str | None = None
    project_version: str | None = None
    git_repo: str | None = None
    model: str | None = None
    board: str | None = None
    mac: str | None = None
    web: bool = False
    password_required: bool = False
    auth_failed: bool = False
    www_username: str | None = None
    wifi_rssi: str | None = None
    uptime_ms: int | None = None
    free_heap: int | None = None
    crash_count: int | None = None
    cert_sha256: str | None = None
    cert_mismatch: bool = False


def schemes_to_try(scheme_mode: str, preferred: str | None = None) -> list[str]:
    """Return the protocols to try, in order.

    A chosen protocol is tried alone. Auto tries the protocol that worked
    last time first, and otherwise HTTP then HTTPS. These controllers ship
    on HTTP; HTTPS is the exception.
    """
    if scheme_mode == SCHEME_HTTP:
        return [SCHEME_HTTP]
    if scheme_mode == SCHEME_HTTPS:
        return [SCHEME_HTTPS]
    if preferred in (SCHEME_HTTP, SCHEME_HTTPS):
        other = SCHEME_HTTP if preferred == SCHEME_HTTPS else SCHEME_HTTPS
        return [preferred, other]
    return [SCHEME_HTTP, SCHEME_HTTPS]


def origin_url(scheme: str, host: str, port: int) -> str:
    """Build ``scheme://host:port/`` for a controller."""
    bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{bracketed}:{port}/"


def homekit_document(payload: Any) -> bool:
    """Return True when ``payload`` is ``build_status_json`` output."""
    if not isinstance(payload, dict):
        return False
    repo = payload.get("gitRepo")
    version = payload.get("firmwareVersion")
    if repo not in HOMEKIT_REPOS:
        return False
    return isinstance(version, str) and bool(version.strip())


_ESPHOME_HTML = (
    "esphome",
    "/0.js",
    "www.js",
    "oi.esphome.io",
    "<esp-app",
    "webserver-v1",
)


def www_authenticate_scheme(header: str | None) -> str | None:
    """Return ``basic`` or ``digest`` when ``header`` is a web-server challenge.

    ESPHome 2026.10 ``AuthMiddlewareHandler`` calls ``requestAuthentication``
    on failure. The default scheme is Basic; ``type: digest`` opts into
    Digest. Either challenge means ``web_server`` is compiled in and
    ``auth:`` is set. A missing header is not that case.
    """
    if not header or not header.strip():
        return None
    scheme = header.strip().split(None, 1)[0].lower()
    if scheme in {"basic", "digest"}:
        return scheme
    return None


def esphome_web_body(path: str, content_type: str, body: str, status: int) -> bool:
    """Return True when an HTTP response is the ESPHome web server.

    Version 1 names ESPHome in the page. Versions 2 and 3 reference
    ``oi.esphome.io`` and ``<esp-app>`` unless ``local: true`` embeds the
    script. ``/0.js`` is only the optional ``js_include`` file. A 401 is
    not decided here; ``www_authenticate_scheme`` covers that.
    """
    if status != 200:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    if path.rstrip("/") in {ESPHOME_JS_PATH.rstrip("/"), "/www.js"}:
        return "javascript" in media or media in {
            "application/javascript",
            "text/javascript",
        }
    if "html" not in media and media not in {"text/plain", ""}:
        return False
    lowered = body.lower()
    return any(marker in lowered for marker in _ESPHOME_HTML)


def restart_path_from_events(text: str) -> str | None:
    """Return the Restart button's POST path from an ``/events`` dump.

    ``set_json_id`` writes ``id`` as ``button/<name>`` (or
    ``button/<device>/<name>`` when the entity has a sub-device). The
    action segment is ``press``. The name in stock ratgdo YAML is
    ``Restart``, which is not the old object id ``restart``.
    """
    import json

    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw or raw[0] not in "{[":
            continue
        try:
            payload = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        domain = _text(payload.get("domain")) or ""
        if domain and domain != "button":
            continue
        name = _text(payload.get("name")) or ""
        entity_id = _text(payload.get("id")) or ""
        if name.lower() != "restart" and not entity_id.lower().endswith("/restart"):
            continue
        if name and name.lower() != "restart":
            continue
        parts = [quote(part, safe="") for part in entity_id.split("/") if part]
        if not parts or parts[0] != "button":
            continue
        return "/" + "/".join([*parts, "press"])
    return None


def _text(value: Any) -> str | None:
    """Return a stripped string, or None."""
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _int(value: Any) -> int | None:
    """Return an int, or None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _from_homekit(
    scheme: str,
    payload: dict[str, Any],
    *,
    fingerprint: str | None,
    hint: Candidate | None,
) -> ProbeResult:
    """Build a successful HomeKit result from ``/status.json``."""
    distance = payload["distanceSensor"] if "distanceSensor" in payload else None
    if isinstance(distance, bool):
        distance_sensor: bool | None = distance
    else:
        distance_sensor = None
    model = _text(hint.model if hint else None)
    git_repo = _text(payload.get("gitRepo"))
    return ProbeResult(
        ok=True,
        scheme=scheme,
        ssl_error=False,
        firmware=FIRMWARE_HOMEKIT,
        name=_text(payload.get("deviceName")) or (hint.name if hint else None),
        firmware_version=_text(payload.get("firmwareVersion")),
        esphome_version=hint.esphome_version if hint else None,
        project_name=hint.project_name if hint else None,
        project_version=hint.project_version if hint else None,
        git_repo=git_repo,
        model=model,
        board=classify_board(
            project_name=hint.project_name if hint else None,
            model=model,
            git_repo=git_repo,
            distance_sensor=distance_sensor,
        ),
        mac=normalize_mac(_text(payload.get("macAddress")))
        or (hint.mac if hint else None),
        web=True,
        password_required=bool(payload.get("passwordRequired")),
        www_username=_text(payload.get("userName")),
        wifi_rssi=_text(payload.get("wifiRSSI")),
        uptime_ms=_int(payload.get("upTime")),
        free_heap=_int(payload.get("freeHeap")),
        crash_count=_int(payload.get("crashCount")),
        cert_sha256=fingerprint,
    )


def _from_esphome(
    scheme: str,
    *,
    fingerprint: str | None,
    hint: Candidate | None,
    web: bool,
    password_required: bool = False,
    auth_failed: bool = False,
) -> ProbeResult:
    """Build an ESPHome result. ``web`` is false when only mDNS identified it."""
    project = hint.project_name if hint else None
    version = hint.project_version if hint else None
    return ProbeResult(
        ok=True,
        scheme=scheme,
        ssl_error=False,
        firmware=FIRMWARE_ESPHOME,
        name=(hint.name if hint else None) or project or "ratgdo",
        firmware_version=version,
        esphome_version=hint.esphome_version if hint else None,
        project_name=project,
        project_version=version,
        model=hint.model if hint else None,
        board=classify_board(
            project_name=project,
            model=hint.model if hint else None,
        )
        if hint
        else None,
        mac=hint.mac if hint else None,
        web=web,
        password_required=password_required,
        auth_failed=auth_failed,
        cert_sha256=fingerprint,
    )


def _ssl_failure(err: BaseException) -> bool:
    """Return True when the failure is a certificate problem."""
    if isinstance(
        err, ssl.SSLError | aiohttp.ClientSSLError | ServerFingerprintMismatch
    ):
        return True
    return "SSL" in type(err).__name__ or "Certificate" in type(err).__name__


def _headers_for(
    username: str | None,
    password: str | None,
) -> dict[str, str]:
    """Return the HomeKit ``X-API-Key`` header when a password is saved."""
    if not password:
        return {}
    user = username or DEFAULT_USERNAME
    return {"X-API-Key": api_key(user, password)}


async def _read_response(
    response: ClientResponse,
) -> tuple[Any, str, str, str | None]:
    """Return JSON-or-None, text, content type, and the leaf fingerprint."""
    fingerprint = peer_fingerprint(response)
    content_type = response.headers.get("Content-Type", "")
    raw = await response.read()
    if raw[:2] == b"\x1f\x8b":
        import gzip

        try:
            raw = gzip.decompress(raw)
        except OSError, EOFError:
            pass
    text = raw.decode("utf-8", errors="replace")
    payload: Any = None
    if "json" in content_type.lower() or text[:1] in "[{":
        try:
            payload = await _json_from_text(text)
        except ValueError:
            payload = None
    return payload, text, content_type, fingerprint


async def _json_from_text(text: str) -> Any:
    """Parse JSON without requiring aiohttp's content-type check."""
    import json

    return json.loads(text)


async def async_probe(
    hass: HomeAssistant,
    host: str,
    port: int = DEFAULT_PORT,
    scheme_mode: str = SCHEME_AUTO,
    verify_ssl: bool = False,
    preferred: str | None = None,
    *,
    pinned_sha256: str | None = None,
    hint: Candidate | None = None,
    username: str | None = None,
    password: str | None = None,
) -> ProbeResult:
    """Probe ``host`` and return the first ratgdo identity, or a failure.

    A stored fingerprint that does not match sets ``cert_mismatch`` and
    does not fall through to the other protocol: the device answered TLS.
    """
    timeout = ClientTimeout(total=PROBE_TIMEOUT)
    pin = None if verify_ssl else normalize_fingerprint(pinned_sha256)
    saw_ssl = False
    captured: str | None = None
    for scheme in schemes_to_try(scheme_mode, preferred):
        base = origin_url(scheme, host, port)
        try:
            result = await _probe_scheme(
                hass,
                base,
                scheme,
                timeout,
                verify_ssl=verify_ssl,
                pin=pin,
                hint=hint,
                username=username,
                password=password,
            )
        except TimeoutError:
            _LOGGER.debug("Probe %s timed out", base)
            continue
        except ServerFingerprintMismatch as err:
            got = err.got.hex() if err.got else None
            _LOGGER.debug("Probe %s certificate pin did not match", base)
            return await _observe_after_mismatch(
                hass, base, timeout, got, hint, username, password
            )
        except (ClientError, OSError, ssl.SSLError) as err:
            if _ssl_failure(err):
                saw_ssl = True
                captured = (
                    await _capture_after_ssl_error(hass, base, timeout) or captured
                )
            _LOGGER.debug("Probe %s failed: %s", base, err)
            if scheme_mode == SCHEME_HTTPS and _ssl_failure(err):
                break
            continue
        if result is None:
            continue
        if result.cert_mismatch or result.ok:
            return result
        if result.ssl_error:
            saw_ssl = True
            captured = result.cert_sha256 or captured
            if scheme_mode == SCHEME_HTTPS:
                break
    if hint is not None and hint.firmware == FIRMWARE_ESPHOME and hint.project_name:
        _LOGGER.debug(
            "No web UI at %s:%s; keeping the ESPHome advertisement for %s",
            host,
            port,
            hint.project_name,
        )
        return _from_esphome(SCHEME_HTTP, fingerprint=captured, hint=hint, web=False)
    return ProbeResult(
        ok=False,
        scheme=None,
        ssl_error=saw_ssl,
        cert_sha256=captured,
    )


async def _probe_scheme(
    hass: HomeAssistant,
    base: str,
    scheme: str,
    timeout: ClientTimeout,
    *,
    verify_ssl: bool,
    pin: str | None,
    hint: Candidate | None,
    username: str | None,
    password: str | None,
) -> ProbeResult | None:
    """Try one scheme. None means try the next scheme."""
    if scheme != SCHEME_HTTPS:
        return await _identify(
            hass,
            base,
            scheme,
            timeout,
            verify=False,
            ssl_param=False,
            hint=hint,
            username=username,
            password=password,
        )
    if verify_ssl:
        return await _probe_authority(hass, base, timeout, hint, username, password)
    if pin:
        return await _identify(
            hass,
            base,
            SCHEME_HTTPS,
            timeout,
            verify=False,
            ssl_param=pinned_ssl(pin),
            hint=hint,
            username=username,
            password=password,
            fingerprint_fallback=pin,
        )
    return await _identify(
        hass,
        base,
        SCHEME_HTTPS,
        timeout,
        verify=False,
        ssl_param=unverified_context(),
        hint=hint,
        username=username,
        password=password,
        observe=True,
    )


async def _probe_authority(
    hass: HomeAssistant,
    base: str,
    timeout: ClientTimeout,
    hint: Candidate | None,
    username: str | None,
    password: str | None,
) -> ProbeResult | None:
    """Validate the certificate against the system trust store."""
    try:
        return await _identify(
            hass,
            base,
            SCHEME_HTTPS,
            timeout,
            verify=True,
            ssl_param=True,
            hint=hint,
            username=username,
            password=password,
        )
    except (ClientError, OSError, ssl.SSLError) as err:
        if not _ssl_failure(err):
            raise
        fingerprint = await _capture_after_ssl_error(hass, base, timeout)
        _LOGGER.debug("Probe %s failed authority validation: %s", base, err)
        return ProbeResult(
            ok=False,
            scheme=SCHEME_HTTPS,
            ssl_error=True,
            cert_sha256=fingerprint,
        )


async def _identify(
    hass: HomeAssistant,
    base: str,
    scheme: str,
    timeout: ClientTimeout,
    *,
    verify: bool,
    ssl_param: Any,
    hint: Candidate | None,
    username: str | None,
    password: str | None,
    fingerprint_fallback: str | None = None,
    observe: bool = False,
) -> ProbeResult | None:
    """GET the identity documents on one origin."""
    session = async_get_clientsession(hass, verify_ssl=verify)
    headers = _headers_for(username, password)
    status_url = f"{base.rstrip('/')}{STATUS_PATH}"
    async with session.get(
        status_url,
        timeout=timeout,
        allow_redirects=False,
        ssl=ssl_param,
        headers=headers or None,
    ) as response:
        payload, _text_body, _content_type, fingerprint = await _read_response(response)
    fingerprint = fingerprint or fingerprint_fallback
    if observe and fingerprint is None and homekit_document(payload):
        fingerprint = await _leaf_on_new_connection(status_url, timeout)
    if homekit_document(payload):
        result = _from_homekit(scheme, payload, fingerprint=fingerprint, hint=hint)
        return await _check_auth(
            session,
            base,
            timeout,
            ssl_param,
            result,
            username,
            password,
        )
    page = await _fetch(
        session,
        page_url := base if base.endswith("/") else f"{base}/",
        timeout,
        ssl_param,
        headers={"Accept-Encoding": "identity"},
    )
    if page is None:
        return None
    page_status, body, content_type, page_fp, challenge = page
    fingerprint = fingerprint or page_fp or fingerprint_fallback
    if esphome_web_body("/", content_type, body, page_status):
        return _from_esphome(scheme, fingerprint=fingerprint, hint=hint, web=True)
    if (
        page_status == 401
        and www_authenticate_scheme(challenge)
        and (hint is None or hint.firmware != FIRMWARE_HOMEKIT)
    ):
        failed = False
        if password:
            authed = await _retry_challenge(
                session,
                page_url,
                timeout,
                ssl_param,
                challenge,
                username=username or DEFAULT_USERNAME,
                password=password,
                method="GET",
                uri="/",
            )
            failed = not authed
        return _from_esphome(
            scheme,
            fingerprint=fingerprint,
            hint=hint,
            web=True,
            password_required=True,
            auth_failed=failed,
        )
    script_url = f"{base.rstrip('/')}{ESPHOME_JS_PATH}"
    script = await _fetch(session, script_url, timeout, ssl_param)
    if script is not None:
        script_status, body, content_type, _fp, _challenge = script
        if esphome_web_body(ESPHOME_JS_PATH, content_type, body, script_status):
            return _from_esphome(scheme, fingerprint=fingerprint, hint=hint, web=True)
    _LOGGER.debug("Probe %s is not a ratgdo web UI", base)
    return None


async def _fetch(
    session: aiohttp.ClientSession,
    url: str,
    timeout: ClientTimeout,
    ssl_param: Any,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, str, str | None, str | None] | None:
    """GET ``url``. None means the connection failed and the caller should stop."""
    try:
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            ssl=ssl_param,
            headers=headers,
        ) as response:
            _payload, text, content_type, fingerprint = await _read_response(response)
            return (
                response.status,
                text,
                content_type,
                fingerprint,
                response.headers.get("WWW-Authenticate"),
            )
    except (ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Probe %s failed: %s", url, err)
        return None


async def _retry_challenge(
    session: aiohttp.ClientSession,
    url: str,
    timeout: ClientTimeout,
    ssl_param: Any,
    challenge: str | None,
    *,
    username: str,
    password: str,
    method: str,
    uri: str,
) -> bool:
    """Return True when saved credentials satisfy ``WWW-Authenticate``."""
    authorization = authorization_for_challenge(
        challenge,
        username=username,
        password=password,
        method=method,
        uri=uri,
    )
    if authorization is None and www_authenticate_scheme(challenge) == "basic":
        authorization = basic_authorization(username, password)
    if not authorization:
        return False
    try:
        async with session.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=False,
            ssl=ssl_param,
            headers={AUTHORIZATION: authorization, "Accept-Encoding": "identity"},
        ) as response:
            return response.status == 200
    except (ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Auth retry %s failed: %s", url, err)
        return False


async def async_discover_restart_path(
    hass: HomeAssistant,
    *,
    scheme: str,
    host: str,
    port: int,
    verify_ssl: bool,
    pinned_sha256: str | None,
    username: str | None,
    password: str | None,
) -> str | None:
    """Read ``/events`` until the Restart button's action URL appears.

    The stream is the entity list (``state_detail_all``). It is not kept
    open. A missing password, or a password the device rejects, returns
    None instead of guessing ``/button/restart/press``.
    """
    verify, ssl_param = _security(scheme, verify_ssl, pinned_sha256)
    if ssl_param is None and scheme == SCHEME_HTTPS:
        return None
    session = async_get_clientsession(hass, verify_ssl=verify)
    base = origin_url(scheme, host, port)
    url = f"{base.rstrip('/')}/events"
    headers: dict[str, str] = {
        "Accept": "text/event-stream",
        "Accept-Encoding": "identity",
    }
    if password:
        headers[AUTHORIZATION] = basic_authorization(
            username or DEFAULT_USERNAME, password
        )
    timeout = ClientTimeout(total=3, sock_connect=PROBE_TIMEOUT, sock_read=2)
    try:
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            ssl=ssl_param,
            headers=headers,
        ) as response:
            if response.status == 401 and password:
                authorization = authorization_for_challenge(
                    response.headers.get("WWW-Authenticate"),
                    username=username or DEFAULT_USERNAME,
                    password=password,
                    method="GET",
                    uri="/events",
                )
                if not authorization:
                    return None
                headers = dict(headers)
                headers[AUTHORIZATION] = authorization
            elif response.status == 200:
                return await _read_event_stream(response)
            else:
                return None
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            ssl=ssl_param,
            headers=headers,
        ) as response:
            if response.status != 200:
                return None
            return await _read_event_stream(response)
    except (ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Restart lookup %s failed: %s", url, err)
        return None


async def _read_event_stream(response: ClientResponse) -> str | None:
    """Return the Restart path from the first chunk of an event stream.

    The device keeps ``/events`` open. A quiet socket ends the read, and
    whatever has already arrived is still parsed.
    """
    parts: list[str] = []
    size = 0
    try:
        async for chunk in response.content.iter_chunked(4096):
            parts.append(chunk.decode("utf-8", errors="replace"))
            size += len(chunk)
            found = restart_path_from_events("".join(parts))
            if found is not None or size >= 65536:
                return found
    except ClientError, OSError, TimeoutError:
        return restart_path_from_events("".join(parts))
    return restart_path_from_events("".join(parts))


async def _check_auth(
    session: aiohttp.ClientSession,
    base: str,
    timeout: ClientTimeout,
    ssl_param: Any,
    result: ProbeResult,
    username: str | None,
    password: str | None,
) -> ProbeResult:
    """Confirm a saved HomeKit password. No password is not a failure."""
    if not result.password_required or not password:
        return result
    headers = _headers_for(username or result.www_username, password)
    url = f"{base.rstrip('/')}{AUTH_PATH}"
    try:
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            ssl=ssl_param,
            headers=headers,
        ) as response:
            status = response.status
    except (ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Auth check %s failed: %s", url, err)
        return result
    if status == 403:
        _LOGGER.debug("Saved password was rejected by %s", url)
        return replace(result, auth_failed=True)
    return result


async def _capture_after_ssl_error(
    hass: HomeAssistant, base: str, timeout: ClientTimeout
) -> str | None:
    """Read the leaf after a rejected handshake so the flow can show it."""
    url = f"{base.rstrip('/')}{STATUS_PATH}"
    try:
        return await _leaf_on_new_connection(url, timeout)
    except (ClientError, OSError, ssl.SSLError, TimeoutError) as err:
        _LOGGER.debug("Could not read the certificate from %s: %s", url, err)
        return None


async def _observe_after_mismatch(
    hass: HomeAssistant,
    base: str,
    timeout: ClientTimeout,
    got: str | None,
    hint: Candidate | None,
    username: str | None,
    password: str | None,
) -> ProbeResult:
    """Re-read the identity after a pin mismatch. ``ok`` stays false."""
    try:
        observed = await _identify(
            hass,
            base,
            SCHEME_HTTPS,
            timeout,
            verify=False,
            ssl_param=unverified_context(),
            hint=hint,
            username=username,
            password=password,
            fingerprint_fallback=got,
            observe=True,
        )
    except (ClientError, OSError, ssl.SSLError, TimeoutError) as err:
        _LOGGER.debug("Probe %s mismatched and could not be re-read: %s", base, err)
        observed = None
    if observed is not None and observed.ok:
        return replace(
            observed,
            ok=False,
            ssl_error=True,
            cert_mismatch=True,
            cert_sha256=observed.cert_sha256 or got,
        )
    return ProbeResult(
        ok=False,
        scheme=SCHEME_HTTPS,
        ssl_error=True,
        cert_sha256=got,
        cert_mismatch=True,
    )


async def _leaf_on_new_connection(url: str, timeout: ClientTimeout) -> str | None:
    """Return the leaf SHA-256 from a handshake this code still holds."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    limit = timeout.total or PROBE_TIMEOUT
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=unverified_context(), server_hostname=host
            ),
            limit,
        )
    except TimeoutError, OSError, ssl.SSLError:
        return None
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError, OSError:
            pass
    if not der:
        return None
    return fingerprint_sha256(der)


async def async_reboot(
    hass: HomeAssistant,
    *,
    scheme: str,
    host: str,
    port: int,
    firmware: str,
    verify_ssl: bool,
    pinned_sha256: str | None,
    username: str | None,
    password: str | None,
    esphome_path: str | None = None,
) -> bool:
    """Reboot the controller. HomeKit's route is open; ESPHome's needs the web UI.

    Returns True when the device accepted the request. A connection drop
    after the bytes are sent is treated as success for HomeKit, because
    ``handle_reboot`` stops the server immediately after the response.
    ESPHome uses the Restart path learned from ``/events``. There is no
    fallback to ``/button/restart/press``.
    """
    if firmware == FIRMWARE_HOMEKIT:
        path = REBOOT_PATH
        method = "POST"
    elif firmware == FIRMWARE_ESPHOME:
        if not esphome_path or not esphome_path.startswith("/button/"):
            return False
        path = esphome_path
        method = "POST"
    else:
        return False
    base = origin_url(scheme, host, port)
    url = f"{base.rstrip('/')}{path}"
    verify, ssl_param = _security(scheme, verify_ssl, pinned_sha256)
    if ssl_param is None and scheme == SCHEME_HTTPS:
        _LOGGER.debug("Reboot %s skipped; certificate is not pinned", url)
        return False
    session = async_get_clientsession(hass, verify_ssl=verify)
    headers = _headers_for(username, password)
    if firmware == FIRMWARE_ESPHOME and password:
        headers = dict(headers)
        headers[AUTHORIZATION] = basic_authorization(
            username or DEFAULT_USERNAME, password
        )
    timeout = ClientTimeout(total=PROBE_TIMEOUT)
    try:
        async with session.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=False,
            ssl=ssl_param,
            headers=headers or None,
        ) as response:
            status = response.status
            challenge = response.headers.get("WWW-Authenticate")
    except (ClientError, OSError, TimeoutError) as err:
        if firmware == FIRMWARE_HOMEKIT:
            _LOGGER.debug("Reboot %s closed the connection: %s", url, err)
            return True
        _LOGGER.debug("Reboot %s failed: %s", url, err)
        return False
    if status in {200, 204}:
        return True
    if status == 401 and firmware == FIRMWARE_ESPHOME and password:
        return await _retry_challenge(
            session,
            url,
            timeout,
            ssl_param,
            challenge,
            username=username or DEFAULT_USERNAME,
            password=password,
            method="POST",
            uri=path,
        )
    _LOGGER.debug("Reboot %s returned HTTP %s", url, status)
    return False


def _security(
    scheme: str, verify_ssl: bool, pinned_sha256: str | None
) -> tuple[bool, Any]:
    """Return ``(verify_session, ssl arg)``. ``ssl arg`` None means no pin yet."""
    if scheme != SCHEME_HTTPS:
        return False, False
    if verify_ssl:
        return True, True
    fingerprint = normalize_fingerprint(pinned_sha256)
    if fingerprint is None:
        return False, None
    return False, pinned_ssl(fingerprint)
