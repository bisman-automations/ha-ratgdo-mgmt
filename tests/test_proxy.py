"""The admin proxy: no bearer token, gzip rewrite, and device auth."""

from __future__ import annotations

import gzip
from typing import Any

from aiohttp import web
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ratgdo_mgmt.auth import api_key
from custom_components.ratgdo_mgmt.const import DOMAIN, PROXY_SANDBOX
from custom_components.ratgdo_mgmt.proxy import (
    async_proxy_url,
    proxy_prefix,
    rewrite_text,
    session_token,
)
from custom_components.ratgdo_mgmt.tls import async_load_proxy_key
from homeassistant.components.http.auth import DATA_SIGN_SECRET
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


async def _admin_user(hass: Any) -> Any:
    for user in await hass.auth.async_get_users():
        if user.is_admin and not user.system_generated:
            return user
    return await hass.auth.async_create_user("Admin", group_ids=["system-admin"])


async def admin_prefix(
    hass: Any, entry_id: str, *, device_id: str = "manual:1", seconds: int | None = None
) -> str:
    """Return a proxy prefix with a session for an administrator."""
    user = await _admin_user(hass)
    await async_load_proxy_key(hass)
    extra = {} if seconds is None else {"seconds": seconds}
    return proxy_prefix(
        entry_id, device_id, session_token(hass, user.id, entry_id, device_id, **extra)
    )


def _sandboxed(response: Any) -> None:
    """The page can never run on Home Assistant's origin."""
    policies = response.headers.getall("Content-Security-Policy", [])
    assert PROXY_SANDBOX in policies
    assert all("allow-same-origin" not in policy for policy in policies)
    assert response.headers.get("Access-Control-Allow-Origin") == "*"
    assert "Access-Control-Allow-Credentials" not in response.headers
    assert response.headers.get("Referrer-Policy") == "no-referrer"


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
    anonymous = await hass_client_no_auth()
    refused = await anonymous.get(
        f"/api/ratgdo_mgmt/proxy/{entry.entry_id}/manual:1/nope/"
    )
    assert refused.status == 401
    _sandboxed(refused)

    prefix = await admin_prefix(hass, entry.entry_id)
    admin = await hass_client()
    # The test client sends Home Assistant's bearer token; it must never
    # reach the controller.
    page = await admin.get(f"{prefix}/")
    text = await page.text()
    assert page.status == 200, text
    assert "settings" in text
    assert f'<base href="{prefix}/">' in text
    assert f"{prefix}/settings" in text
    assert f"{prefix}/favicon.ico" in text
    assert seen["authorization"] == ""
    assert seen["api_key"] == api_key("admin", "password")
    _sandboxed(page)
    assert "Set-Cookie" not in page.headers
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
    prefix = await admin_prefix(hass, entry.entry_id)
    admin = await hass_client()
    page = await admin.get(f"{prefix}/")
    text = await page.text()
    assert page.status == 200, text
    assert "esp-app" in text
    _sandboxed(page)
    assert any(item[2].startswith("Basic ") for item in seen)
    pressed = await admin.post(f"{prefix}/button/Restart/press")
    assert pressed.status == 200
    legacy = await admin.post(f"{prefix}/button/restart/press")
    assert legacy.status == 200
    events = await admin.get(f"{prefix}/events")
    assert events.status == 200
    _sandboxed(events)
    assert "button/Restart" in await events.text()
    await runner.cleanup()


async def _no_restart(*_args: Any, **_kwargs: Any) -> None:
    """Skip the live /events read; this test drives the proxy itself."""
    return None


def test_rewrite_and_signed_url_helpers(hass: Any) -> None:
    """Root-relative URLs gain the proxy prefix."""
    prefix = "/api/ratgdo_mgmt/proxy/entry/manual:1/session"
    html = rewrite_text(
        '<html><head></head><body><a href="/setgdo">x</a></body></html>',
        "text/html",
        prefix=prefix,
        origins=("http://192.0.2.20:80", "https://192.0.2.20:80"),
    )
    assert f'href="{prefix}/setgdo"' in html
    assert HOST


async def _simple_entry(hass: Any, monkeypatch: pytest.MonkeyPatch, port: int) -> Any:
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
    return entry


async def test_sessions_are_bound_and_expire(
    hass: Any,
    hass_client: Any,
    hass_client_no_auth: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session is for one controller and one admin, and it expires. Home
    Assistant's own token alone opens nothing."""

    async def handler(_request: web.Request) -> web.StreamResponse:
        return web.Response(
            text="<html><head></head><body>ok</body></html>", content_type="text/html"
        )

    runner, port = await _serve(handler)
    try:
        entry = await _simple_entry(hass, monkeypatch, port)
        client = await hass_client_no_auth()
        admin = await hass_client()
        bearer_only = await admin.get(
            f"/api/ratgdo_mgmt/proxy/{entry.entry_id}/manual:1/x/"
        )
        assert bearer_only.status == 401

        expired = await admin_prefix(hass, entry.entry_id, seconds=-30)
        assert (await client.get(f"{expired}/")).status == 401
        prefix = await admin_prefix(hass, entry.entry_id)
        session = prefix.rsplit("/", 1)[1]
        assert (
            await client.get(
                f"/api/ratgdo_mgmt/proxy/{entry.entry_id}/manual:2/{session}/"
            )
        ).status == 401
        encoded, signature = session.split(".", 1)
        forged = prefix.replace(session, f"{encoded}.{'0' * len(signature)}")
        assert (await client.get(f"{forged}/")).status == 401

        guest = await hass.auth.async_create_user("Guest")
        guest_prefix = proxy_prefix(
            entry.entry_id,
            "manual:1",
            session_token(hass, guest.id, entry.entry_id, "manual:1"),
        )
        assert (await client.get(f"{guest_prefix}/")).status == 403
        assert (await client.get(f"{prefix}/")).status == 200
        assert (
            await async_proxy_url(hass, entry.entry_id, "manual:1", "x") != f"{prefix}/"
        )
    finally:
        await runner.cleanup()


async def test_preflight_is_answered_without_the_controller(
    hass: Any, hass_client_no_auth: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HomeKit page sends X-API-Key, so its calls are preflighted."""
    seen: list[str] = []

    async def handler(request: web.Request) -> web.StreamResponse:
        seen.append(request.method)
        return web.Response(text="ok")

    runner, port = await _serve(handler)
    try:
        entry = await _simple_entry(hass, monkeypatch, port)
        prefix = await admin_prefix(hass, entry.entry_id)
        client = await hass_client_no_auth()
        answer = await client.options(
            f"{prefix}/setgdo",
            headers={
                "Origin": "null",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-api-key",
            },
        )
        assert answer.status == 204
        _sandboxed(answer)
        assert answer.headers["Access-Control-Allow-Headers"] == "x-api-key"
        assert "OPTIONS" not in seen
    finally:
        await runner.cleanup()


async def test_the_key_is_the_proxys_own(
    hass: Any, hass_storage: dict[str, Any]
) -> None:
    """Sessions use ratgdo Mgmt's own random key, never Home Assistant's."""
    hass.data.pop(DATA_SIGN_SECRET, None)
    key = await async_load_proxy_key(hass)
    assert len(key) == 64
    assert DATA_SIGN_SECRET not in hass.data
    assert hass_storage["ratgdo_mgmt.proxy_key"]["data"]["key"] == key.decode()
    hass.data[DOMAIN].pop("proxy_key")
    assert await async_load_proxy_key(hass) == key


def test_hook_gives_the_sandboxed_page_storage_and_posts_anywhere() -> None:
    """A sandboxed page throws on storage; the hook replaces it. Its origin
    is opaque, so it posts to the panel without naming one."""
    from custom_components.ratgdo_mgmt.proxy import hook_javascript

    script = hook_javascript(
        "/api/ratgdo_mgmt/proxy/e/manual:1/s",
        ("http://192.0.2.20:80", "https://192.0.2.20:80"),
    )
    assert 'for (const name of ["localStorage", "sessionStorage"])' in script
    assert 'Object.defineProperty(document, "cookie"' in script
    assert 'parent.postMessage({ source: SOURCE, ok: true }, "*")' in script


async def test_websocket_reaches_the_controller(
    hass: Any, hass_client_no_auth: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A websocket through the proxy used to fail before it connected."""

    async def handler(request: web.Request) -> web.StreamResponse:
        if request.headers.get("Upgrade", "").lower() == "websocket":
            socket = web.WebSocketResponse()
            await socket.prepare(request)
            async for message in socket:
                await socket.send_str(f"echo:{message.data}")
            return socket
        return web.Response(text="ok")

    runner, port = await _serve(handler)
    try:
        entry = await _simple_entry(hass, monkeypatch, port)
        prefix = await admin_prefix(hass, entry.entry_id)
        client = await hass_client_no_auth()
        async with client.ws_connect(f"{prefix}/ws") as websocket:
            await websocket.send_str("hi")
            assert await websocket.receive_str() == "echo:hi"
    finally:
        await runner.cleanup()
