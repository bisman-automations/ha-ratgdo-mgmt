"""The admin proxy: no bearer token, gzip rewrite, and device auth."""

from __future__ import annotations

import gzip
from typing import Any

from aiohttp import web
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ratgdo_mgmt.auth import api_key
from custom_components.ratgdo_mgmt.const import DOMAIN, PROXY_COOKIE
from custom_components.ratgdo_mgmt.proxy import proxy_prefix, rewrite_text
from tests.common import HOST, MAC, STATUS


async def _serve(handler: Any) -> tuple[web.AppRunner, int]:
    """Start a local stand-in and return its runner and port."""
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # noqa: SLF001
    return runner, port


def _record(host: str, port: int) -> dict[str, Any]:
    """One HomeKit controller aimed at the stand-in."""
    return {
        "name": "Garage Door ABCDEF",
        "host": host,
        "port": port,
        "scheme": "http",
        "scheme_mode": "http",
        "verify_ssl": False,
        "cert_sha256": None,
        "firmware": "homekit",
        "firmware_version": "3.5.6",
        "git_repo": "homekit-ratgdo32",
        "model": "ratgdo_32",
        "board": "ratgdo32",
        "mac": MAC,
        "web": True,
        "password_required": True,
        "username": "admin",
        "password": "password",
        "ignored": False,
        "source": "manual",
    }


async def test_proxy_strips_bearer_rewrites_gzip_and_sends_api_key(
    hass: Any,
    hass_client: Any,
    hass_client_no_auth: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An admin sees the page. The controller never sees the HA token."""
    seen: dict[str, str] = {}

    async def handler(request: web.Request) -> web.StreamResponse:
        seen["authorization"] = request.headers.get("Authorization", "")
        seen["api_key"] = request.headers.get("X-API-Key", "")
        if request.path == "/status.json":
            return web.json_response(STATUS)
        if request.path in {"/", "/index.html"}:
            html = (
                "<html><head></head><body>"
                "<a href='/settings'>settings</a>"
                "<img src='/favicon.ico'>"
                "</body></html>"
            )
            return web.Response(
                body=gzip.compress(html.encode()),
                content_type="text/html",
                headers={"Content-Encoding": "gzip"},
            )
        return web.Response(status=404, text="missing")

    runner, port = await _serve(handler)

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        from tests.common import probe_ok

        return probe_ok()

    monkeypatch.setattr("custom_components.ratgdo_mgmt.coordinator.async_probe", _probe)
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="ratgdo Mgmt",
        data={},
        options={"devices": {"manual:1": _record("127.0.0.1", port)}},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    prefix = proxy_prefix(entry.entry_id, "manual:1")
    anonymous = await hass_client_no_auth()
    refused = await anonymous.get(f"{prefix}/")
    assert refused.status == 401

    admin = await hass_client()
    # The test client already sends Home Assistant's bearer token. Passing
    # another Authorization header would replace it and fail the login.
    page = await admin.get(f"{prefix}/")
    text = await page.text()
    assert page.status == 200, text
    assert "settings" in text
    assert f'<base href="{prefix}/">' in text
    assert f"{prefix}/settings" in text
    assert f"{prefix}/favicon.ico" in text
    assert seen["authorization"] == ""
    assert seen["api_key"] == api_key("admin", "password")
    assert PROXY_COOKIE in page.cookies
    assert "\x1f" not in text
    await runner.cleanup()


async def test_proxy_answers_esphome_basic_and_forwards_actions(
    hass: Any,
    hass_client: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Basic auth, a name-based POST, the old press path, and /events."""
    seen: list[tuple[str, str, str]] = []

    async def handler(request: web.Request) -> web.StreamResponse:
        auth = request.headers.get("Authorization", "")
        seen.append((request.method, request.path, auth))
        if not auth.startswith("Basic "):
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
        if request.method == "POST" and request.path in {
            "/button/Restart/press",
            "/button/restart/press",
        }:
            return web.Response(status=200, text="ok")
        if request.path == "/":
            html = (
                "<html><head></head><body><esp-app></esp-app>"
                "<script src='https://oi.esphome.io/v3/www.js'></script>"
                "</body></html>"
            )
            return web.Response(text=html, content_type="text/html")
        return web.Response(status=404, text="missing")

    runner, port = await _serve(handler)
    record = _record("127.0.0.1", port)
    record["firmware"] = "esphome"
    record["git_repo"] = None
    record["password_required"] = True

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        from tests.common import probe_ok

        return probe_ok(firmware="esphome", web=True, password_required=True)

    monkeypatch.setattr("custom_components.ratgdo_mgmt.coordinator.async_probe", _probe)
    monkeypatch.setattr(
        "custom_components.ratgdo_mgmt.coordinator.async_discover_restart_path",
        _no_restart,
    )
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="ratgdo Mgmt",
        data={},
        options={"devices": {"manual:1": record}},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    prefix = proxy_prefix(entry.entry_id, "manual:1")
    admin = await hass_client()
    page = await admin.get(f"{prefix}/")
    text = await page.text()
    assert page.status == 200, text
    assert "esp-app" in text
    assert any(item[2].startswith("Basic ") for item in seen)
    pressed = await admin.post(f"{prefix}/button/Restart/press")
    assert pressed.status == 200
    legacy = await admin.post(f"{prefix}/button/restart/press")
    assert legacy.status == 200
    events = await admin.get(f"{prefix}/events")
    assert events.status == 200
    assert "button/Restart" in await events.text()
    await runner.cleanup()


async def _no_restart(*_args: Any, **_kwargs: Any) -> None:
    """Skip the live /events read; this test drives the proxy itself."""
    return None


def test_rewrite_and_signed_url_helpers(hass: Any) -> None:
    """Root-relative URLs gain the proxy prefix."""
    prefix = "/api/ratgdo_mgmt/proxy/entry/manual:1"
    html = rewrite_text(
        '<html><head></head><body><a href="/setgdo">x</a></body></html>',
        "text/html",
        prefix=prefix,
        origins=("http://192.0.2.20:80", "https://192.0.2.20:80"),
    )
    assert f'href="{prefix}/setgdo"' in html
    assert HOST
