"""ESPHome 2026.10 web_server: auth, local assets, and the Restart path."""

from __future__ import annotations

import base64
import gzip
from typing import Any

from aiohttp import web

from custom_components.ratgdo_mgmt.client import (
    async_discover_restart_path,
    async_probe,
    async_reboot,
)
from custom_components.ratgdo_mgmt.discovery import Candidate


def _hint() -> Candidate:
    """The advertisement Donavan's v2.5i board sends."""
    return Candidate(
        host="127.0.0.1",
        port=80,
        name="Garage Large Door Opener ESPHome",
        firmware="esphome",
        project_name="ratgdo.v25iboard_secplusv1",
        project_version="2.5i",
        esphome_version="2026.10.2",
    )


def _v3_html() -> str:
    """Version 3 index: remote www.js, no /0.js."""
    return (
        "<!DOCTYPE html><html><head></head><body><esp-app></esp-app>"
        "<script src='https://oi.esphome.io/v3/www.js'></script>"
        "</body></html>"
    )


def _basic(header: str) -> str:
    """Return the username:password from a Basic header, or empty."""
    if not header.startswith("Basic "):
        return ""
    try:
        return base64.b64decode(header.split(" ", 1)[1]).decode()
    except ValueError, UnicodeError:
        return ""


async def _serve(handler: Any) -> tuple[web.AppRunner, int]:
    """Start one stand-in web_server."""
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # noqa: SLF001
    return runner, port


async def test_each_open_page_shape(hass: Any, socket_enabled: None) -> None:
    """Serve v2, then v3, then a gzipped local bundle, one process each."""

    async def make(kind: str) -> None:
        async def handler(request: web.Request) -> web.StreamResponse:
            if request.path != "/":
                return web.Response(status=404, text="no /0.js")
            if kind == "local":
                return web.Response(
                    body=gzip.compress(b"<html><esp-app></esp-app>esphome local"),
                    content_type="text/html",
                    headers={"Content-Encoding": "gzip"},
                )
            if kind == "v2":
                text = "<html><script src='https://oi.esphome.io/v2/www.js'></script>"
            else:
                text = _v3_html()
            return web.Response(text=text, content_type="text/html")

        runner, port = await _serve(handler)
        try:
            result = await async_probe(hass, "127.0.0.1", port, "http", hint=_hint())
            assert result.web is True, kind
            assert result.password_required is False, kind
            assert result.auth_failed is False, kind
        finally:
            await runner.cleanup()

    for kind in ("v2", "v3", "local"):
        await make(kind)


async def test_basic_auth_401_means_the_page_exists(hass: Any, socket_enabled: None) -> None:
    """Donavan's YAML: auth without type is Basic. 401 is a web UI.

    No password stays password_required and not auth_failed. A wrong
    password is auth_failed. The right password opens the v3 page.
    /0.js is not served (local: true).
    """
    challenges = {"count": 0}

    async def handler(request: web.Request) -> web.StreamResponse:
        if request.path == "/0.js":
            return web.Response(status=404, text="not compiled in")
        if request.method == "GET" and request.path == "/":
            user = _basic(request.headers.get("Authorization", ""))
            if user != "admin:secret":
                challenges["count"] += 1
                return web.Response(
                    status=401,
                    headers={"WWW-Authenticate": 'Basic realm="Login Required"'},
                    text="Unauthorized",
                )
            return web.Response(text=_v3_html(), content_type="text/html")
        return web.Response(status=404, text="missing")

    runner, port = await _serve(handler)
    try:
        missing = await async_probe(hass, "127.0.0.1", port, "http", hint=_hint())
        assert missing.web is True
        assert missing.password_required is True
        assert missing.auth_failed is False
        assert missing.firmware == "esphome"

        rejected = await async_probe(
            hass,
            "127.0.0.1",
            port,
            "http",
            hint=_hint(),
            username="admin",
            password="nope",
        )
        assert rejected.web is True
        assert rejected.password_required is True
        assert rejected.auth_failed is True

        opened = await async_probe(
            hass,
            "127.0.0.1",
            port,
            "http",
            hint=_hint(),
            username="admin",
            password="secret",
        )
        assert opened.web is True
        assert opened.password_required is True
        assert opened.auth_failed is False
        assert challenges["count"] >= 3
    finally:
        await runner.cleanup()


async def test_digest_challenge_is_answered(hass: Any, socket_enabled: None) -> None:
    """type: digest sends a Digest challenge, then accepts the retry."""
    nonces = iter(["nonce-1", "nonce-2"])

    async def handler(request: web.Request) -> web.StreamResponse:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Digest "):
            nonce = next(nonces)
            return web.Response(
                status=401,
                headers={
                    "WWW-Authenticate": (
                        f'Digest realm="Login Required", nonce="{nonce}", qop="auth"'
                    )
                },
                text="Unauthorized",
            )
        assert 'uri="/"' in header
        return web.Response(text=_v3_html(), content_type="text/html")

    runner, port = await _serve(handler)
    try:
        result = await async_probe(
            hass,
            "127.0.0.1",
            port,
            "http",
            hint=_hint(),
            username="admin",
            password="secret",
        )
        assert result.web is True
        assert result.password_required is True
        assert result.auth_failed is False
    finally:
        await runner.cleanup()


async def test_events_name_is_the_restart_path_and_press_uses_it(
    hass: Any, socket_enabled: None
) -> None:
    """Restart is POST /button/Restart/press, learned from /events."""
    pressed: list[str] = []

    async def handler(request: web.Request) -> web.StreamResponse:
        user = _basic(request.headers.get("Authorization", ""))
        if user != "admin:secret":
            return web.Response(
                status=401,
                headers={"WWW-Authenticate": 'Basic realm="Login Required"'},
                text="Unauthorized",
            )
        if request.path == "/events":
            body = (
                "event: state_detail_all\n"
                'data: {"id":"button/Restart","name":"Restart","domain":"button"}\n\n'
            )
            return web.Response(text=body, content_type="text/event-stream")
        if request.method == "POST":
            pressed.append(request.path)
            return web.Response(status=200, text="ok")
        return web.Response(status=404, text="missing")

    runner, port = await _serve(handler)
    try:
        path = await async_discover_restart_path(
            hass,
            scheme="http",
            host="127.0.0.1",
            port=port,
            verify_ssl=False,
            pinned_sha256=None,
            username="admin",
            password="secret",
        )
        assert path == "/button/Restart/press"
        assert "/button/restart/press" not in pressed
        ok = await async_reboot(
            hass,
            scheme="http",
            host="127.0.0.1",
            port=port,
            firmware="esphome",
            verify_ssl=False,
            pinned_sha256=None,
            username="admin",
            password="secret",
            esphome_path=path,
        )
        assert ok is True
        assert pressed == ["/button/Restart/press"]
        refused = await async_reboot(
            hass,
            scheme="http",
            host="127.0.0.1",
            port=port,
            firmware="esphome",
            verify_ssl=False,
            pinned_sha256=None,
            username="admin",
            password="secret",
            esphome_path=None,
        )
        assert refused is False
    finally:
        await runner.cleanup()
