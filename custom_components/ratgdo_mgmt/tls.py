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
import ssl
from typing import Any

from aiohttp import Fingerprint

from homeassistant.core import HomeAssistant

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


def sign_secret(hass: HomeAssistant) -> bytes:
    """Return the key Home Assistant uses to sign temporary paths.

    Sharing that key means a restart drops proxy cookies the same way it
    drops signed URLs. The key is created on first use, which is what
    ``async_sign_path`` does too.
    """
    from homeassistant.components.http.auth import DATA_SIGN_SECRET

    secret = hass.data.get(DATA_SIGN_SECRET)
    if not isinstance(secret, str) or not secret:
        import secrets

        secret = secrets.token_hex()
        hass.data[DATA_SIGN_SECRET] = secret
    return secret.encode()


def keyed_digest(hass: HomeAssistant, payload: bytes) -> str:
    """Return hex HMAC-SHA256 of ``payload`` under the instance key."""
    return hmac.new(sign_secret(hass), payload, hashlib.sha256).hexdigest()
