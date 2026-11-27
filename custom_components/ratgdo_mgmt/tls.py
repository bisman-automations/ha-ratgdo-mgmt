"""TLS for a ratgdo web port.

Stock ESPHome and HomeKit firmware serve the web UI over plain HTTP on
port 80. HTTPS is here for a controller someone has put behind TLS, and
for the same pinning rules Kiosk Mgmt uses: the first leaf is remembered,
later handshakes must present it, and Verify SSL certificate is the
opt-in for a certificate an authority already signed.

aiohttp's :class:`~aiohttp.Fingerprint` hashes the leaf DER after the
handshake. The first observation has nothing to compare yet, so it uses a
context that does not validate the authority and reads the peer
certificate off the connection. Callers show that fingerprint before
storing it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import ssl
from typing import Any

from aiohttp import Fingerprint

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import DOMAIN

_HEX = frozenset("0123456789abcdef")
_UNVERIFIED: ssl.SSLContext | None = None


def unverified_context() -> ssl.SSLContext:
    """Return a TLS client context that still negotiates, without CA checks.

    Shared on purpose. :class:`ssl.SSLContext` is safe to reuse across
    connections, and building one per probe shows up in profiles.
    """
    global _UNVERIFIED
    if _UNVERIFIED is None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _UNVERIFIED = context
    return _UNVERIFIED


def normalize_fingerprint(value: Any) -> str | None:
    """Return lowercase hex SHA-256, or None when the value is not one.

    Stored records and the repair flow both accept the colon form a person
    would read off a screen.
    """
    if not isinstance(value, str):
        return None
    raw = value.replace(":", "").replace(" ", "").strip().lower()
    if len(raw) != 64 or any(char not in _HEX for char in raw):
        return None
    return raw


def format_fingerprint(value: str) -> str:
    """Return the colon form shown in the config flow, ``AA:BB:...``."""
    raw = normalize_fingerprint(value) or ""
    if len(raw) != 64:
        return value
    return ":".join(raw[i : i + 2] for i in range(0, 64, 2)).upper()


def fingerprint_sha256(der: bytes) -> str:
    """Return the SHA-256 hex digest of a leaf certificate's DER bytes."""
    return hashlib.sha256(der).hexdigest()


def peer_fingerprint(response: object) -> str | None:
    """Return the leaf SHA-256 of an open response, if TLS was used.

    Must be called before the response is released. A plain HTTP response
    and a stand-in used by tests have no SSL object, and both return None.
    """
    connection = getattr(response, "connection", None)
    transport = getattr(connection, "transport", None)
    if transport is None:
        return None
    sslobj = transport.get_extra_info("ssl_object")
    if sslobj is None:
        return None
    der = sslobj.getpeercert(binary_form=True)
    if not der:
        return None
    return fingerprint_sha256(der)


def pinned_ssl(fingerprint: str) -> Fingerprint:
    """Return the aiohttp checker for a stored fingerprint."""
    normalized = normalize_fingerprint(fingerprint)
    if normalized is None:
        raise ValueError("certificate fingerprint must be SHA-256 hex")
    return Fingerprint(bytes.fromhex(normalized))


# The proxy's own signing key, kept in ratgdo Mgmt's storage. Home
# Assistant's signed-path secret belongs to the http component and is not
# touched (hacs/default#14091).
_KEY_STORE = "ratgdo_mgmt.proxy_key"
_KEY_STORE_VERSION = 1
_DATA_KEY = "proxy_key"


async def async_load_proxy_key(hass: HomeAssistant) -> bytes:
    """Return the proxy signing key, creating and saving it the first time.

    The key is random, lives in ``.storage/ratgdo_mgmt.proxy_key`` and is
    cached for the rest of the run, so sessions survive a restart until
    they expire and nothing else in Home Assistant can mint one.
    """
    data: dict[str, Any] = hass.data.setdefault(DOMAIN, {})
    cached = data.get(_DATA_KEY)
    if isinstance(cached, bytes):
        return cached
    store: Store[dict[str, Any]] = Store(hass, _KEY_STORE_VERSION, _KEY_STORE)
    stored = await store.async_load() or {}
    key = stored.get("key") if isinstance(stored, dict) else None
    if not isinstance(key, str) or len(key) < 64:
        key = secrets.token_hex(32)
        await store.async_save({"key": key})
    cached = data.get(_DATA_KEY)
    if isinstance(cached, bytes):
        return cached
    data[_DATA_KEY] = key.encode()
    return data[_DATA_KEY]


def proxy_key(hass: HomeAssistant) -> bytes:
    """Return the loaded key. ``async_load_proxy_key`` must have run first."""
    key = hass.data.get(DOMAIN, {}).get(_DATA_KEY)
    if not isinstance(key, bytes):
        raise RuntimeError("ratgdo Mgmt's proxy key is not loaded")
    return key


def keyed_digest(hass: HomeAssistant, payload: bytes) -> str:
    """Return hex HMAC-SHA256 of ``payload`` under ratgdo Mgmt's own key."""
    return hmac.new(proxy_key(hass), payload, hashlib.sha256).hexdigest()
