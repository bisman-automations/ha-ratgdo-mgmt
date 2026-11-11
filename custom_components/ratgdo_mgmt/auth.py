"""HomeKit-firmware web authentication.

``src/www/functions.js`` (``promptPassword``) and ``src/web.cpp``
(``requestAuthenticated``) implement two equivalent checks:

- ``X-API-Key`` is the hex MD5 of ``username:realm:password``. The realm
  string is ``RATGDO Login Required``. When the header is present the
  firmware compares it to the stored hash and does not look at Digest.
- Otherwise ESP8266 calls ``authenticateDigest`` with that same stored
  hash, and ESP32 calls ``authenticate`` with the plaintext password.
  Both send ``WWW-Authenticate: Digest realm="RATGDO Login Required"``.

A browser sitting on the Home Assistant origin cannot answer that Digest
challenge itself: the ``uri`` it would hash is the proxy path, and the
firmware hashes the path it received (``/setgdo``, ``/auth``, ...). The
proxy therefore builds the Digest header for the upstream URI, and it
forwards ``X-API-Key`` unchanged when the embedded page already set one.

ESPHome's ``web_server`` auth, when a build enables it, is HTTP basic or
HTTP digest (``web_server/__init__.py`` ``AUTH_TYPE_BASIC`` /
``AUTH_TYPE_DIGEST``). The same helpers cover that. Stock ratgdo YAML
does not set ``auth:``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
from typing import Final

from .const import AUTH_REALM

_MD5: Final = "MD5"


def api_key(username: str, password: str, realm: str = AUTH_REALM) -> str:
    """Return the ``X-API-Key`` the HomeKit web UI would send."""
    material = f"{username}:{realm}:{password}".encode()
    return hashlib.md5(material).hexdigest()  # noqa: S324  # firmware requires MD5


def basic_authorization(username: str, password: str) -> str:
    """Return a Basic Authorization value."""
    import base64

    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


@dataclass(slots=True)
class DigestChallenge:
    """The pieces of one ``WWW-Authenticate: Digest`` header."""

    realm: str
    nonce: str
    opaque: str | None = None
    qop: str | None = None
    algorithm: str = _MD5


def _unquote(value: str) -> str:
    """Strip one pair of quotes from a challenge parameter."""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def parse_www_authenticate(header: str | None) -> DigestChallenge | None:
    """Return a Digest challenge, or None when the header is not Digest."""
    if not header:
        return None
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() != "digest":
        return None
    fields: dict[str, str] = {}
    # Parameters are comma-separated. Quoted values may not contain commas
    # in the challenges these devices send (realm, nonce, opaque, qop).
    for piece in rest.split(","):
        name, sep, raw = piece.partition("=")
        if not sep:
            continue
        fields[name.strip().lower()] = _unquote(raw)
    realm = fields.get("realm")
    nonce = fields.get("nonce")
    if not realm or not nonce:
        return None
    qop = fields.get("qop")
    if qop and "auth" in {part.strip() for part in qop.split(",")}:
        qop = "auth"
    elif qop:
        # auth-int needs the body. These devices ask for auth.
        qop = None
    return DigestChallenge(
        realm=realm,
        nonce=nonce,
        opaque=fields.get("opaque"),
        qop=qop,
        algorithm=fields.get("algorithm") or _MD5,
    )


def digest_authorization(
    *,
    username: str,
    password: str,
    method: str,
    uri: str,
    challenge: DigestChallenge,
    cnonce: str | None = None,
    nc: str = "00000001",
) -> str:
    """Return an Authorization header for ``uri`` on the device.

    ``uri`` is the path the firmware sees, including the query string when
    one was sent. It is not the Home Assistant proxy path.
    """
    ha1 = api_key(username, password, challenge.realm)
    ha2 = hashlib.md5(f"{method.upper()}:{uri}".encode()).hexdigest()  # noqa: S324
    if challenge.qop == "auth":
        nonce_count = nc
        client_nonce = cnonce or secrets.token_hex(8)
        response = hashlib.md5(  # noqa: S324
            f"{ha1}:{challenge.nonce}:{nonce_count}:{client_nonce}:auth:{ha2}".encode()
        ).hexdigest()
        parts = [
            f'Digest username="{username}"',
            f'realm="{challenge.realm}"',
            f'nonce="{challenge.nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            "qop=auth",
            f"nc={nonce_count}",
            f'cnonce="{client_nonce}"',
            f"algorithm={challenge.algorithm or _MD5}",
        ]
    else:
        response = hashlib.md5(  # noqa: S324
            f"{ha1}:{challenge.nonce}:{ha2}".encode()
        ).hexdigest()
        parts = [
            f'Digest username="{username}"',
            f'realm="{challenge.realm}"',
            f'nonce="{challenge.nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f"algorithm={challenge.algorithm or _MD5}",
        ]
    if challenge.opaque:
        parts.append(f'opaque="{challenge.opaque}"')
    return ", ".join(parts)


def authorization_for_challenge(
    header: str | None,
    *,
    username: str,
    password: str,
    method: str,
    uri: str,
) -> str | None:
    """Return an Authorization value for a 401 challenge, or None.

    Basic is recognized by the scheme word. Anything that is not Basic or
    Digest is left alone so a future scheme is not answered with a guess.
    """
    if not header:
        return None
    if header.strip().lower().startswith("basic"):
        return basic_authorization(username, password)
    challenge = parse_www_authenticate(header)
    if challenge is None:
        return None
    return digest_authorization(
        username=username,
        password=password,
        method=method,
        uri=uri,
        challenge=challenge,
    )
