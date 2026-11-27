"""Sandboxed reverse proxy to a ratgdo web UI.

The panel's iframe cannot send Home Assistant's bearer token. The panel
asks the ``ratgdo_mgmt/sign_proxy`` websocket command (administrators only)
for a proxy URL. That URL carries a session: an HMAC-signed token naming
the administrator, the entry, the controller and an expiry, signed with
ratgdo Mgmt's own random key (``tls.async_load_proxy_key``). Every request
under the prefix, including POST, EventSource and websockets, is checked
against it, and the administrator must still be an active admin.

The controller's page is never allowed to share Home Assistant's origin
(hacs/default#14091). Every response carries a
``Content-Security-Policy: sandbox`` without ``allow-same-origin``, and the
panel's iframe has the same sandbox, so the page (and anything it loads,
such as ESPHome's ``www.js`` from oi.esphome.io) runs on an opaque origin:
it can't read Home Assistant's storage or tokens or call Home Assistant as
the admin. Opened as a top-level page it gets the same sandbox. A
sandboxed page has no cookies, which is why the session is in the path,
and its requests back to Home Assistant are cross-origin, which is why the
proxy answers CORS (never with credentials) and preflight requests itself.
The injected hook gives the page in-memory ``localStorage``,
``sessionStorage`` and ``document.cookie``.

Home Assistant's ``Authorization: Bearer`` header is never forwarded. The
HomeKit web UI authenticates with ``X-API-Key`` (``functions.js``), which
is forwarded when the page set it and filled in from the saved password
when it did not. A 401 ``WWW-Authenticate`` challenge is answered by this
proxy for the upstream path, because a browser prompt would hash the
Home Assistant path and the firmware hashes ``/setgdo``. ESPHome
``web_server`` basic or digest auth uses the same retry.

HomeKit static files are gzip-compressed before they are stored
(``load_page`` always sets ``Content-Encoding: gzip``). Those bodies are
decompressed, rewritten, and sent uncompressed so ``<base>`` and the hook
can be inserted. The controller is contacted with the pinned certificate
when the record is HTTPS. Responses drop ``X-Frame-Options`` and the CSP
``frame-ancestors`` directive, and add the sandbox policy.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Mapping
import gzip
import hmac
import json
import logging
import re
import time
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from aiohttp import ClientError, ClientTimeout, ClientWSTimeout, WSMsgType, web
from aiohttp.client_exceptions import ServerFingerprintMismatch
from aiohttp.hdrs import AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION
from multidict import CIMultiDict

from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.http import (
    KEY_HASS,
    HomeAssistantView,
    request_handler_factory,
)

from .auth import api_key, authorization_for_challenge, basic_authorization
from .client import origin_url
from .const import (
    ATTR_CERT_SHA256,
    CONF_SCHEME,
    CONF_VERIFY_SSL,
    DOMAIN,
    FIRMWARE_ESPHOME,
    FIRMWARE_HOMEKIT,
    PROXY_HOOK,
    PROXY_SANDBOX,
    PROXY_SESSION_SECONDS,
    PROXY_SOURCE,
    SCHEME_HTTP,
    SCHEME_HTTPS,
)
from .records import credentials_for, devices_from_options
from .tls import async_load_proxy_key, keyed_digest, pinned_ssl

_LOGGER = logging.getLogger(__name__)
_MAX_REWRITE = 8 * 1024 * 1024
_CHUNK = 64 * 1024
_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)
_DROP_RESPONSE = _HOP | frozenset(
    {
        "x-frame-options",
        "strict-transport-security",
        "content-security-policy",
    }
)
_REWRITABLE = (
    "text/html",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "text/plain",
    "application/xml",
    "text/xml",
    "image/svg+xml",
)
_ATTR_URL = re.compile(
    r"""(?P<attr>\b(?:href|src|action|poster|formaction|cite)\s*=\s*)"""
    r"""(?P<quote>["'])(?P<url>[^"']+)(?P=quote)""",
    re.IGNORECASE,
)
_CSS_URL = re.compile(
    r"""url\(\s*(?P<quote>["']?)(?P<url>[^)"']+)(?P=quote)\s*\)""",
    re.IGNORECASE,
)


def device_segment(device_id: str) -> str:
    """Return one path segment. Colons in ``mac:`` and ``fleet:`` ids stay."""
    return quote(device_id, safe=":")


def proxy_prefix(entry_id: str, device_id: str, session: str) -> str:
    """Return the proxy path for one controller and session, without a trailing slash."""
    return f"/api/ratgdo_mgmt/proxy/{entry_id}/{device_segment(device_id)}/{session}"


def session_token(
    hass: HomeAssistant,
    user_id: str,
    entry_id: str,
    device_id: str,
    *,
    seconds: int = PROXY_SESSION_SECONDS,
) -> str:
    """Return a signed session for one admin, entry and controller.

    Base64url and hex only, so it is one safe path segment. The key must be
    loaded (``async_load_proxy_key``).
    """
    payload = json.dumps(
        {
            "e": entry_id,
            "k": device_id,
            "u": user_id,
            "exp": int(time.time()) + seconds,
        },
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{encoded}.{keyed_digest(hass, payload)}"


async def async_proxy_url(
    hass: HomeAssistant, entry_id: str, device_id: str, user_id: str
) -> str:
    """Return the URL the panel's iframe opens for one controller."""
    await async_load_proxy_key(hass)
    session = session_token(hass, user_id, entry_id, device_id)
    return f"{proxy_prefix(entry_id, device_id, session)}/"


def _origins(record: Mapping[str, Any]) -> tuple[str, str]:
    """Return the http and https origins of the controller, including the port."""
    host = str(record[CONF_HOST])
    port = int(record["port"])
    return (
        origin_url(SCHEME_HTTP, host, port).rstrip("/"),
        origin_url(SCHEME_HTTPS, host, port).rstrip("/"),
    )


def _scheme(record: Mapping[str, Any]) -> str:
    """Return the protocol the last successful probe used."""
    scheme = record.get(CONF_SCHEME)
    if scheme in (SCHEME_HTTP, SCHEME_HTTPS):
        return str(scheme)
    return SCHEME_HTTP


def rewrite_location(value: str, *, prefix: str, origins: tuple[str, str]) -> str:
    """Point a redirect at the proxy, keeping it on Home Assistant's origin."""
    for origin in origins:
        if value == origin or _has_boundary(value, origin):
            rest = value[len(origin) :]
            if rest and not rest.startswith(("/", "?", "#")):
                continue
            return prefix + (rest or "/")
    if (
        value.startswith("/")
        and not value.startswith("//")
        and not _already(value, prefix)
    ):
        return prefix + value
    return value


def _has_boundary(value: str, origin: str) -> bool:
    """True when ``value`` starts with ``origin`` and does not swallow a longer host."""
    return value.startswith(origin) and (
        len(value) == len(origin) or value[len(origin)] in "/?#"
    )


def _already(url: str, prefix: str) -> bool:
    """True when a URL is already under the proxy prefix."""
    return url == prefix or url.startswith(prefix + "/")


def strip_frame_ancestors(policy: str) -> str:
    """Remove ``frame-ancestors`` and keep the rest of a CSP."""
    kept: list[str] = []
    for part in policy.split(";"):
        directive = part.strip()
        if not directive:
            continue
        if directive.split()[0].lower() == "frame-ancestors":
            continue
        kept.append(directive)
    return "; ".join(kept)


def rewrite_set_cookie(header: str, *, prefix: str) -> str:
    """Keep a controller cookie on the proxy path and off the controller's domain.

    ``Domain`` would otherwise attach the cookie to the controller's host, which
    the browser never sends back to Home Assistant. ``Path=/`` would attach
    it to every Home Assistant page.
    """
    pieces = [piece.strip() for piece in header.split(";") if piece.strip()]
    if not pieces:
        return header
    rewritten = [pieces[0]]
    saw_path = False
    for piece in pieces[1:]:
        name, _, raw = piece.partition("=")
        if name.lower() == "domain":
            continue
        if name.lower() == "path":
            saw_path = True
            path = raw.strip() or "/"
            if not _already(path, prefix):
                path = prefix if path == "/" else prefix + path
            rewritten.append(f"Path={path}")
            continue
        rewritten.append(piece)
    if not saw_path:
        rewritten.append(f"Path={prefix}")
    return "; ".join(rewritten)


def rewrite_text(
    body: str,
    content_type: str,
    *,
    prefix: str,
    origins: tuple[str, str],
) -> str:
    """Rewrite absolute and root-relative URLs so the app stays on the proxy."""
    text = body
    for origin in origins:
        text = _replace_origin(text, origin, prefix)
    media = content_type.split(";", 1)[0].strip().lower()
    if media == "text/html":
        text = _ATTR_URL.sub(lambda match: _rewrite_attr(match, prefix), text)
        text = _inject_hook(text, prefix)
    elif media == "text/css":
        text = _CSS_URL.sub(lambda match: _rewrite_css(match, prefix), text)
    return text


def _replace_origin(text: str, origin: str, prefix: str) -> str:
    """Replace ``origin`` only when it is a whole origin, not a longer host."""
    parts: list[str] = []
    start = 0
    while True:
        found = text.find(origin, start)
        if found < 0:
            parts.append(text[start:])
            break
        end = found + len(origin)
        if end == len(text) or text[end] in "/?#":
            parts.append(text[start:found])
            parts.append(prefix)
            start = end
            continue
        parts.append(text[start:end])
        start = end
    return "".join(parts)


def _rewrite_attr(match: re.Match[str], prefix: str) -> str:
    """Prefix a root-relative HTML attribute. Already-proxied URLs stay put."""
    url = match.group("url")
    if url.startswith("/") and not url.startswith("//") and not _already(url, prefix):
        url = prefix + url
    return f"{match.group('attr')}{match.group('quote')}{url}{match.group('quote')}"


def _rewrite_css(match: re.Match[str], prefix: str) -> str:
    """Prefix a root-relative CSS ``url()``."""
    url = match.group("url")
    quote = match.group("quote")
    if url.startswith("/") and not url.startswith("//") and not _already(url, prefix):
        url = prefix + url
    return f"url({quote}{url}{quote})"


def _inject_hook(html: str, prefix: str) -> str:
    """Insert ``<base>`` and the rewrite hook as the first thing in ``<head>``."""
    snippet = f'<base href="{prefix}/"><script src="{prefix}/{PROXY_HOOK}"></script>'
    match = re.search(r"<head\b[^>]*>", html, re.IGNORECASE)
    if match:
        return html[: match.end()] + snippet + html[match.end() :]
    return snippet + html


def hook_javascript(prefix: str, origins: tuple[str, str]) -> str:
    """Return the script that rewrites URLs the static pass cannot see.

    Fetch, XHR, websockets, and history run after the document is parsed.
    The constants are JSON so a controller name cannot break out of the script.
    """
    http_origin, https_origin = origins
    ws_origins = [
        "ws" + http_origin.removeprefix("http"),
        "wss" + https_origin.removeprefix("https"),
    ]
    return f"""
(() => {{
  const PREFIX = {json.dumps(prefix)};
  const ORIGINS = {json.dumps([http_origin, https_origin])};
  const WS_ORIGINS = {json.dumps(ws_origins)};
  const SOURCE = {json.dumps(PROXY_SOURCE)};

  // The page is sandboxed on an opaque origin, where localStorage,
  // sessionStorage and document.cookie throw. Give it in-memory ones that
  // last as long as the page.
  function memoryStorage() {{
    const items = new Map();
    return {{
      get length() {{ return items.size; }},
      key(index) {{ return [...items.keys()][index] ?? null; }},
      getItem(name) {{
        const value = items.get(String(name));
        return value === undefined ? null : value;
      }},
      setItem(name, value) {{ items.set(String(name), String(value)); }},
      removeItem(name) {{ items.delete(String(name)); }},
      clear() {{ items.clear(); }},
    }};
  }}
  for (const name of ["localStorage", "sessionStorage"]) {{
    let usable = false;
    try {{ usable = Boolean(window[name]); }} catch (_err) {{ usable = false; }}
    if (!usable) {{
      try {{
        Object.defineProperty(window, name, {{ value: memoryStorage(), configurable: true }});
      }} catch (_err) {{}}
    }}
  }}
  try {{
    void document.cookie;
  }} catch (_err) {{
    const jar = new Map();
    try {{
      Object.defineProperty(document, "cookie", {{
        configurable: true,
        get() {{ return [...jar].map(([k, v]) => k + "=" + v).join("; "); }},
        set(text) {{
          const pair = String(text).split(";", 1)[0];
          const at = pair.indexOf("=");
          if (at > 0) jar.set(pair.slice(0, at).trim(), pair.slice(at + 1).trim());
        }},
      }});
    }} catch (_err2) {{}}
  }}

  function boundary(url, origin) {{
    return url === origin || url.startsWith(origin + "/")
      || url.startsWith(origin + "?") || url.startsWith(origin + "#");
  }}

  function rewrite(url) {{
    if (typeof url !== "string" || !url) return url;
    for (const origin of ORIGINS) {{
      if (boundary(url, origin)) return PREFIX + url.slice(origin.length);
    }}
    for (const origin of WS_ORIGINS) {{
      if (boundary(url, origin)) {{
        const rest = url.slice(origin.length);
        const page = location.protocol === "https:" ? "wss:" : "ws:";
        return page + "//" + location.host + PREFIX + rest;
      }}
    }}
    if (url.startsWith("/") && !url.startsWith("//") && url !== PREFIX
        && !url.startsWith(PREFIX + "/")) {{
      return PREFIX + url;
    }}
    return url;
  }}

  const origFetch = window.fetch;
  if (origFetch) {{
    window.fetch = function (input, init) {{
      if (typeof input === "string") input = rewrite(input);
      else if (input && typeof input.url === "string") {{
        input = new Request(rewrite(input.url), input);
      }}
      return origFetch.call(this, input, init);
    }};
  }}

  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) {{
    return origOpen.call(this, method, rewrite(String(url)), ...rest);
  }};

  const OrigWS = window.WebSocket;
  function ProxiedWS(url, protocols) {{
    const next = rewrite(String(url));
    if (protocols === undefined) return new OrigWS(next);
    return new OrigWS(next, protocols);
  }}
  ProxiedWS.prototype = OrigWS.prototype;
  ProxiedWS.CONNECTING = OrigWS.CONNECTING;
  ProxiedWS.OPEN = OrigWS.OPEN;
  ProxiedWS.CLOSING = OrigWS.CLOSING;
  ProxiedWS.CLOSED = OrigWS.CLOSED;
  window.WebSocket = ProxiedWS;

  if (window.EventSource) {{
    const OrigES = window.EventSource;
    window.EventSource = function (url, options) {{
      return new OrigES(rewrite(String(url)), options);
    }};
    window.EventSource.prototype = OrigES.prototype;
  }}

  const origPush = history.pushState.bind(history);
  const origReplace = history.replaceState.bind(history);
  history.pushState = (state, title, url) =>
    origPush(state, title, typeof url === "string" ? rewrite(url) : url);
  history.replaceState = (state, title, url) =>
    origReplace(state, title, typeof url === "string" ? rewrite(url) : url);

  const origAssign = location.assign.bind(location);
  const origReplaceLoc = location.replace.bind(location);
  location.assign = (url) => origAssign(rewrite(String(url)));
  location.replace = (url) => origReplaceLoc(rewrite(String(url)));

  const origOpenWindow = window.open;
  window.open = (url, target, features) =>
    origOpenWindow.call(window, url ? rewrite(String(url)) : url, target, features);

  // The page's origin is opaque, so it can't name the panel's; the panel
  // checks the message comes from its own iframe.
  parent.postMessage({{ source: SOURCE, ok: true }}, "*");
}})();
"""


# Sent with every proxied response, the hook and the error pages. The page
# runs on an opaque origin, so its requests back here are cross-origin: they
# never carry credentials, and the session in the path is what authorizes
# them, so any origin may read the answer.
SANDBOX_HEADERS: dict[str, str] = {
    "Content-Security-Policy": PROXY_SANDBOX,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Expose-Headers": "*",
    # The session is in the URL; don't hand it to another site.
    "Referrer-Policy": "no-referrer",
}
# The controller's own copies of the headers the proxy sets.
_SANDBOX_KEYS = frozenset(
    {
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-expose-headers",
        "referrer-policy",
    }
)


def _preflight(request: web.Request) -> web.Response:
    """Answer a CORS preflight from the sandboxed page without the controller."""
    headers = dict(SANDBOX_HEADERS)
    headers["Access-Control-Allow-Methods"] = request.headers.get(
        "Access-Control-Request-Method", "GET"
    )
    wanted = request.headers.get("Access-Control-Request-Headers")
    if wanted:
        headers["Access-Control-Allow-Headers"] = wanted
    headers["Access-Control-Max-Age"] = "600"
    return web.Response(status=204, headers=headers)


def _error_page(status: int, title: str, message: str) -> web.Response:
    """Return a small page the panel can tell apart from a blank frame."""
    safe_title = json.dumps(title)[1:-1]
    safe_message = json.dumps(message)[1:-1]
    body = (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<title>{safe_title}</title></head><body>"
        f"<h1>{safe_title}</h1><p>{safe_message}</p>"
        "<script>parent.postMessage({source:"
        f"{json.dumps(PROXY_SOURCE)},ok:false}}, '*');</script>"
        "</body></html>"
    )
    return web.Response(
        status=status, text=body, content_type="text/html", headers=SANDBOX_HEADERS
    )


def _media_type(header: str | None) -> str:
    """Return the content type without parameters."""
    if not header:
        return ""
    return header.split(";", 1)[0].strip().lower()


class RatgdoProxyView(HomeAssistantView):
    """Proxy one controller's admin origin under Home Assistant."""

    # aiohttp treats ``{name:regex}`` as a regular expression, not a Flask-style
    # converter. ``.+`` is the rest of the path, including nested segments.
    # Device ids contain colons (``manual:1``), which is fine: ``{device_id}``
    # is one segment, and the path is everything after it.
    url = "/api/ratgdo_mgmt/proxy/{entry_id}/{device_id}/{session}/{path:.+}"
    extra_urls = [
        "/api/ratgdo_mgmt/proxy/{entry_id}/{device_id}/{session}",
        "/api/ratgdo_mgmt/proxy/{entry_id}/{device_id}/{session}/",
    ]
    name = "api:ratgdo_mgmt:proxy"
    # The session in the path is the credential; see ``_authorize``.
    requires_auth = False

    def __init__(self) -> None:
        """Bind every verb to the same handler. The web UI uses more than GET."""
        for method in ("post", "put", "patch", "delete", "head", "options"):
            setattr(self, method, self.get)

    def register(
        self, hass: HomeAssistant, app: web.Application, router: web.UrlDispatcher
    ) -> None:
        """Register the routes without Home Assistant's CORS handling.

        Home Assistant answers a CORS preflight itself for every view and
        refuses an origin it wasn't configured with. The sandboxed page's
        origin is "null", so its requests with ``X-API-Key`` never reached
        this view. The proxy answers its own preflights (``_preflight``),
        and only for a valid session.
        """
        assert self.url is not None
        for method in ("get", "post", "delete", "put", "patch", "head", "options"):
            handler = request_handler_factory(hass, self, getattr(self, method))
            for url in (self.url, *self.extra_urls):
                router.add_route(method, url, handler)

    async def get(
        self,
        request: web.Request,
        entry_id: str,
        device_id: str,
        session: str,
        path: str = "",
    ) -> web.StreamResponse:
        """Forward one request, or serve the rewrite hook."""
        user, failure = await _authorize(request, entry_id, device_id, session)
        if failure is not None or user is None:
            return _error_page(
                failure or 401,
                "Not allowed",
                "This link has expired or isn't for an administrator. "
                "Open the controller again from the ratgdo Mgmt panel.",
            )
        record = _record(request, entry_id, device_id)
        if record is None:
            return _error_page(
                404,
                "ratgdo not found",
                "That controller is not in ratgdo Mgmt.",
            )
        if request.method == "OPTIONS" and request.headers.get(
            "Access-Control-Request-Method"
        ):
            return _preflight(request)
        prefix = proxy_prefix(entry_id, device_id, session)
        if path.rstrip("/") == PROXY_HOOK:
            origins = _origins(record)
            return web.Response(
                text=hook_javascript(prefix, origins),
                content_type="application/javascript",
                headers={**SANDBOX_HEADERS, "Cache-Control": "no-store"},
            )
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await _proxy_websocket(request, record, path)
        return await _proxy_http(request, record, path, prefix)


def _record(
    request: web.Request, entry_id: str, device_id: str
) -> dict[str, Any] | None:
    """Return the stored controller, ignoring ones the user has hidden."""
    hass: HomeAssistant = request.app[KEY_HASS]
    entry = hass.config_entries.async_get_entry(entry_id)
    if entry is None or entry.domain != DOMAIN:
        return None
    record = devices_from_options(entry.options).get(device_id)
    if record is None or record.get("ignored"):
        return None
    return record


async def _authorize(
    request: web.Request, entry_id: str, device_id: str, session: str
) -> tuple[Any, int | None]:
    """Return ``(user, None)`` or ``(None, status)`` for the session in the path.

    401: no session, a forged one, one for another controller, or an expired
    one. 403: the user is no longer an administrator.
    """
    hass: HomeAssistant = request.app[KEY_HASS]
    if "." not in session:
        return None, 401
    encoded, signature = session.split(".", 1)
    padding = "=" * (-len(encoded) % 4)
    try:
        payload = base64.urlsafe_b64decode((encoded + padding).encode())
    except ValueError:
        return None, 401
    await async_load_proxy_key(hass)
    if not hmac.compare_digest(keyed_digest(hass, payload), signature):
        return None, 401
    try:
        data = json.loads(payload)
    except ValueError:
        return None, 401
    if not isinstance(data, dict):
        return None, 401
    if data.get("e") != entry_id or data.get("k") != device_id:
        return None, 401
    try:
        expires = int(data.get("exp") or 0)
    except TypeError, ValueError:
        return None, 401
    if expires < int(time.time()):
        return None, 401
    user = await hass.auth.async_get_user(str(data.get("u") or ""))
    if user is None or not user.is_active:
        return None, 401
    if not user.is_admin:
        return None, 403
    return user, None


def _forward_query(request: web.Request) -> list[tuple[str, str]]:
    """Return the query to send to the controller."""
    return list(request.query.items())


def _forward_request_headers(
    request: web.Request,
    upstream_origin: str,
    record: Mapping[str, Any],
) -> dict[str, str]:
    """Copy request headers the controller should see.

    Home Assistant's bearer token is dropped here and never put back.
    ``X-API-Key`` from the HomeKit page is forwarded. When the page did
    not send one and a password is saved, the proxy fills in the key the
    firmware compares in ``requestAuthenticated``. Origin and Referer are
    rewritten so a controller that checks them still sees its own origin.
    """
    headers: dict[str, str] = {}
    saw_api_key = False
    for key, value in request.headers.items():
        lower = key.lower()
        if lower in _HOP or lower in {AUTHORIZATION.lower(), "cookie"}:
            continue
        if lower == "x-api-key":
            saw_api_key = True
        if lower == "origin":
            headers[key] = upstream_origin
            continue
        if lower == "referer":
            headers[key] = f"{upstream_origin}/"
            continue
        headers[key] = value
    if not saw_api_key and record.get("firmware") == FIRMWARE_HOMEKIT:
        username, password = credentials_for(record)
        if password:
            headers["X-API-Key"] = api_key(username or "admin", password)
    elif record.get("firmware") == FIRMWARE_ESPHOME:
        username, password = credentials_for(record)
        if password and AUTHORIZATION not in headers:
            # Stock YAML has no web_server auth. A saved password is sent
            # as Basic, which is what web_server auth defaults to. Digest
            # is answered later, after the device sends a nonce.
            headers[AUTHORIZATION] = basic_authorization(username or "admin", password)
    headers["Accept-Encoding"] = "identity"
    return headers


def _response_headers(
    upstream: Any,
    *,
    prefix: str,
    origins: tuple[str, str],
    rewritten: bool,
    drop_encoding: bool = False,
) -> CIMultiDict[str]:
    """Build the headers the browser should see."""
    headers: CIMultiDict[str] = CIMultiDict()
    for key, value in upstream.headers.items():
        lower = key.lower()
        if (
            lower in _DROP_RESPONSE
            or lower in _SANDBOX_KEYS
            or (drop_encoding and lower == "content-encoding")
        ):
            continue
        if lower == "set-cookie":
            headers.add(key, rewrite_set_cookie(value, prefix=prefix))
            continue
        if lower == LOCATION.lower():
            headers.add(key, rewrite_location(value, prefix=prefix, origins=origins))
            continue
        if rewritten and lower == CONTENT_LENGTH.lower():
            continue
        headers.add(key, value)
    for key, value in SANDBOX_HEADERS.items():
        headers[key] = value
    policy = upstream.headers.get("Content-Security-Policy")
    if policy:
        stripped = strip_frame_ancestors(policy)
        if stripped:
            # Both policies apply; the sandbox one can only take away.
            headers.add("Content-Security-Policy", stripped)
    return headers


async def _proxy_http(
    request: web.Request,
    record: Mapping[str, Any],
    path: str,
    prefix: str,
) -> web.StreamResponse:
    """Stream one HTTP response, rewriting text bodies before they go out."""
    security = _security(record)
    if security is None:
        return _error_page(
            503,
            "Certificate not pinned yet",
            "ratgdo Mgmt has not recorded this controller's certificate. "
            "Wait for the next refresh, or reconfigure the controller.",
        )
    verify, ssl_param = security
    hass: HomeAssistant = request.app[KEY_HASS]
    session = async_get_clientsession(hass, verify_ssl=verify)
    origins = _origins(record)
    scheme = _scheme(record)
    origin = origins[1] if scheme == SCHEME_HTTPS else origins[0]
    upstream = _upstream_url(record, path, _forward_query(request))
    timeout = ClientTimeout(total=60, sock_connect=10)
    body = await request.read() if request.can_read_body else None
    headers = _forward_request_headers(request, origin, record)
    try:
        response_cm = session.request(
            request.method,
            upstream,
            headers=headers,
            data=body,
            allow_redirects=False,
            ssl=ssl_param,
            timeout=timeout,
            skip_auto_headers=["Accept-Encoding"],
            auto_decompress=False,
        )
        upstream_response = await response_cm.__aenter__()
    except ServerFingerprintMismatch:
        _LOGGER.warning("Proxy to %s refused a changed certificate", upstream)
        return _error_page(
            409,
            "Certificate changed",
            "This controller presented a different certificate from the one "
            "ratgdo Mgmt has pinned. Accept the new certificate from the repair.",
        )
    except (ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Proxy to %s failed: %s", upstream, err)
        return _error_page(
            502,
            "Controller didn't answer",
            "Home Assistant could not reach the controller's web page.",
        )
    try:
        username, password = credentials_for(record)
        if upstream_response.status == 401 and password:
            challenge = upstream_response.headers.get("WWW-Authenticate")
            parts = urlsplit(upstream)
            uri = parts.path or "/"
            if parts.query:
                uri = f"{uri}?{parts.query}"
            auth_value = authorization_for_challenge(
                challenge,
                username=username or "admin",
                password=password,
                method=request.method,
                uri=uri,
            )
            if auth_value:
                await response_cm.__aexit__(None, None, None)
                headers = dict(headers)
                headers[AUTHORIZATION] = auth_value
                response_cm = session.request(
                    request.method,
                    upstream,
                    headers=headers,
                    data=body,
                    allow_redirects=False,
                    ssl=ssl_param,
                    timeout=timeout,
                    skip_auto_headers=["Accept-Encoding"],
                    auto_decompress=False,
                )
                upstream_response = await response_cm.__aenter__()
        return await _send_upstream(
            request,
            upstream_response,
            prefix=prefix,
            origins=origins,
        )
    finally:
        await response_cm.__aexit__(None, None, None)


async def _send_upstream(
    request: web.Request,
    upstream: Any,
    *,
    prefix: str,
    origins: tuple[str, str],
) -> web.StreamResponse:
    """Write the upstream response, buffering text that has to be rewritten."""
    media = _media_type(upstream.headers.get(CONTENT_TYPE))
    length = upstream.content_length
    rewrite = media in _REWRITABLE and (length is None or length <= _MAX_REWRITE)
    if rewrite:
        body = await upstream.read()
        decoded = _gunzip(body, upstream.headers.get("Content-Encoding"))
        headers = _response_headers(
            upstream,
            prefix=prefix,
            origins=origins,
            rewritten=True,
            drop_encoding=decoded is not None,
        )
        if decoded is not None:
            body = decoded
        if len(body) <= _MAX_REWRITE:
            text = body.decode("utf-8", errors="replace")
            text = rewrite_text(
                text,
                upstream.headers.get(CONTENT_TYPE) or media,
                prefix=prefix,
                origins=origins,
            )
            body = text.encode()
        return web.Response(status=upstream.status, headers=headers, body=body)
    headers = _response_headers(
        upstream,
        prefix=prefix,
        origins=origins,
        rewritten=False,
    )
    stream = web.StreamResponse(status=upstream.status, headers=headers)
    await stream.prepare(request)
    async for chunk in upstream.content.iter_chunked(_CHUNK):
        await stream.write(chunk)
    await stream.write_eof()
    return stream


def _gunzip(body: bytes, encoding: str | None) -> bytes | None:
    """Return decompressed bytes, or None when ``body`` is not gzip.

    HomeKit ``load_page`` gzips HTML, CSS, JS, and images even when the
    client asked for identity. Rewritten text has to be plain bytes. None
    means the caller should keep the original bytes and the gzip header.
    """
    # aiohttp is asked not to decompress (auto_decompress=False) so the
    # gzip magic is still here. A body that is already plain text is left
    # alone; the caller drops Content-Encoding only when this returns bytes.
    del encoding
    if body[:2] != b"\x1f\x8b":
        return None
    try:
        return gzip.decompress(body)
    except OSError, EOFError:
        _LOGGER.debug("Leaving a body that claimed to be gzip")
        return None


def _upstream_url(
    record: Mapping[str, Any], path: str, query: list[tuple[str, str]]
) -> str:
    """Build the controller URL for a proxied path."""
    base = origin_url(_scheme(record), str(record[CONF_HOST]), int(record["port"]))
    suffix = path.lstrip("/")
    url = f"{base}{suffix}" if suffix else base
    if query:
        url = f"{url}?{urlencode(query)}"
    return url


def _security(record: Mapping[str, Any]) -> tuple[bool, Any] | None:
    """Return ``(verify_session, ssl arg)``, or None when a pin is required and missing."""
    if _scheme(record) != SCHEME_HTTPS:
        return False, False
    if record.get(CONF_VERIFY_SSL):
        return True, True
    fingerprint = record.get(ATTR_CERT_SHA256)
    if not fingerprint:
        return None
    try:
        return False, pinned_ssl(str(fingerprint))
    except ValueError:
        _LOGGER.debug("Ignoring an unreadable certificate pin")
        return None


async def _proxy_websocket(
    request: web.Request,
    record: Mapping[str, Any],
    path: str,
) -> web.StreamResponse:
    """Bridge a browser websocket to the controller over the pinned connection."""
    security = _security(record)
    if security is None:
        return _error_page(
            503,
            "Certificate not pinned yet",
            "ratgdo Mgmt has not recorded this controller's certificate.",
        )
    verify, ssl_param = security
    hass: HomeAssistant = request.app[KEY_HASS]
    session = async_get_clientsession(hass, verify_ssl=verify)
    scheme = "wss" if _scheme(record) == SCHEME_HTTPS else "ws"
    http_scheme = SCHEME_HTTPS if scheme == "wss" else SCHEME_HTTP
    base = origin_url(http_scheme, str(record[CONF_HOST]), int(record["port"]))
    suffix = path.lstrip("/")
    upstream_url = f"{scheme}://{base.split('://', 1)[1]}{suffix}"
    query = _forward_query(request)
    if query:
        upstream_url = f"{upstream_url}?{urlencode(query)}"
    protocols = [
        item.strip()
        for item in request.headers.get("Sec-WebSocket-Protocol", "").split(",")
        if item.strip()
    ]
    client = web.WebSocketResponse(protocols=protocols)
    await client.prepare(request)
    try:
        upstream = await session.ws_connect(
            upstream_url,
            ssl=ssl_param,
            headers=_forward_request_headers(request, base.rstrip("/"), record),
            protocols=protocols,
            timeout=ClientWSTimeout(ws_close=10),
        )
    except (ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Websocket proxy to %s failed: %s", upstream_url, err)
        await client.close(code=1011, message=b"upstream unavailable")
        return client

    async def _from_browser() -> None:
        async for msg in client:
            if msg.type == WSMsgType.TEXT:
                await upstream.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await upstream.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.ERROR):
                await upstream.close()
                break

    async def _from_device() -> None:
        async for msg in upstream:
            if msg.type == WSMsgType.TEXT:
                await client.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await client.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.ERROR):
                await client.close()
                break

    browser_task = asyncio.create_task(_from_browser())
    device_task = asyncio.create_task(_from_device())
    try:
        await asyncio.wait(
            {browser_task, device_task}, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        browser_task.cancel()
        device_task.cancel()
        await asyncio.gather(browser_task, device_task, return_exceptions=True)
        if not upstream.closed:
            await upstream.close()
        if not client.closed:
            await client.close()
    return client


def register_proxy(hass: HomeAssistant) -> None:
    """Register the proxy view once."""
    if hass.data[DOMAIN].get("proxy"):
        return
    hass.http.register_view(RatgdoProxyView())
    hass.data[DOMAIN]["proxy"] = True
