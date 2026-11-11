"""Load the sidebar in headless Chrome against mock controller pages.

The browser talks to Home Assistant. Home Assistant's proxy talks to the
stand-in. Screenshots are written when RATGDO_ARTIFACTS is set.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import shutil
from tempfile import TemporaryDirectory
from typing import Any

from aiohttp import ClientSession, web
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.ratgdo_mgmt.const import DOMAIN
from custom_components.ratgdo_mgmt.proxy import signed_proxy_url
from tests.common import STATUS


async def _admin_refresh(hass: Any) -> str:
    """Return the refresh-token id of an administrator."""
    for user in await hass.auth.async_get_users():
        if user.is_admin and user.refresh_tokens:
            return next(iter(user.refresh_tokens))
    raise AssertionError("no admin refresh token")


_CHROME = shutil.which("google-chrome") or shutil.which("chromium")
_ARTIFACTS = os.environ.get("RATGDO_ARTIFACTS", "")


async def _evaluate(
    debug_port: int, method: str, params: dict[str, Any] | None = None
) -> Any:
    """Run one CDP command against the first page."""
    async with (
        ClientSession() as session,
        session.get(f"http://127.0.0.1:{debug_port}/json/list") as response,
    ):
        targets = await response.json()
    page = next(item for item in targets if item.get("type") == "page")
    async with (
        ClientSession() as session,
        session.ws_connect(page["webSocketDebuggerUrl"]) as websocket,
    ):
        await websocket.send_json({"id": 1, "method": method, "params": params or {}})
        while True:
            message = await websocket.receive_json()
            if message.get("id") == 1:
                return message.get("result")


async def _serve(html: str, *, gzip_body: bool) -> tuple[web.AppRunner, int]:
    """Serve one page, optionally gzipped the way HomeKit firmware does."""

    async def handler(request: web.Request) -> web.Response:
        if request.path == "/status.json":
            return web.json_response(STATUS)
        body = html.encode()
        headers = {}
        if gzip_body:
            body = gzip.compress(body)
            headers["Content-Encoding"] = "gzip"
        return web.Response(body=body, content_type="text/html", headers=headers)

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # noqa: SLF001
    return runner, port


def _device(name: str, host: str, port: int, firmware: str) -> dict[str, Any]:
    """A stored controller pointed at a stand-in."""
    return {
        "name": name,
        "host": host,
        "port": port,
        "scheme": "http",
        "scheme_mode": "http",
        "verify_ssl": False,
        "firmware": firmware,
        "firmware_version": "3.5.6" if firmware == "homekit" else "2.5",
        "project_name": None
        if firmware == "homekit"
        else "ratgdo.v25board_esp32_secplus2",
        "board": "ratgdo32" if firmware == "homekit" else "ratgdo25",
        "mac": "aa:bb:cc:dd:ee:ff",
        "web": True,
        "password_required": firmware == "homekit",
        "username": "admin",
        "password": "password",
        "ignored": False,
        "source": "manual",
    }


async def test_panel_shows_proxied_pages(
    hass: Any, hass_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The iframe renders both mock pages through the proxy."""
    if _CHROME is None:
        pytest.skip("chrome is not installed")
    homekit_html = """<!DOCTYPE html><html><head><title>HomeKit</title></head>
<body style="margin:0;background:#1b1b1b;color:#f2f2f2;font-family:sans-serif">
<main style="padding:24px"><h1>ratgdo for HomeKit</h1>
<p>Firmware 3.5.6</p><p>Door status is managed elsewhere.</p>
<button>Reboot</button></main></body></html>"""
    esphome_html = """<!DOCTYPE html><html><head><title>ESPHome</title></head>
<body style="margin:0;background:#f4f6f8;color:#182026;font-family:sans-serif">
<main style="padding:24px"><h1>ESPHome</h1>
<p>ratgdo v2.5 web server</p><p>esphome web_server</p></main></body></html>"""
    home_runner, home_port = await _serve(homekit_html, gzip_body=True)
    esp_runner, esp_port = await _serve(esphome_html, gzip_body=False)

    async def _probe(*_args: Any, **_kwargs: Any) -> Any:
        from tests.common import probe_ok

        return probe_ok(web=True)

    monkeypatch.setattr("custom_components.ratgdo_mgmt.coordinator.async_probe", _probe)
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="ratgdo Mgmt",
        data={},
        options={
            "devices": {
                "homekit:1": _device("Garage A", "127.0.0.1", home_port, "homekit"),
                "esphome:1": _device("Garage B", "127.0.0.1", esp_port, "esphome"),
            }
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    refresh = await _admin_refresh(hass)
    signed = {
        "homekit:1": signed_proxy_url(
            hass, entry.entry_id, "homekit:1", refresh_token_id=refresh
        ),
        "esphome:1": signed_proxy_url(
            hass, entry.entry_id, "esphome:1", refresh_token_id=refresh
        ),
    }
    devices = [
        {
            "id": "homekit:1",
            "name": "Garage A",
            "host": "127.0.0.1",
            "firmware": "homekit",
            "firmware_version": "3.5.6",
            "online": True,
            "web": True,
            "last_seen": None,
            "url": f"http://127.0.0.1:{home_port}/",
        },
        {
            "id": "esphome:1",
            "name": "Garage B",
            "host": "127.0.0.1",
            "firmware": "esphome",
            "firmware_version": "2.5",
            "project_name": "ratgdo.v25board_esp32_secplus2",
            "board": "ratgdo25",
            "mac": "aa:bb:cc:dd:ee:ff",
            "online": True,
            "web": True,
            "last_seen": None,
            "url": f"http://127.0.0.1:{esp_port}/",
        },
    ]
    page = f"""<!DOCTYPE html><html><body style="margin:0">
<script src="/ratgdo_mgmt/ratgdo-mgmt-panel.js"></script>
<ratgdo-mgmt-panel></ratgdo-mgmt-panel>
<script>
const el = document.querySelector("ratgdo-mgmt-panel");
const signed = {json.dumps(signed)};
const devices = {json.dumps(devices)};
el.hass = {{
  connection: {{
    subscribeMessage(callback) {{
      callback({{devices}});
      return Promise.resolve(() => {{}});
    }},
    sendMessagePromise(msg) {{
      return Promise.resolve({{url: signed[msg.device_id], expires_in: 300}});
    }}
  }},
  callService() {{ return Promise.resolve(); }}
}};
</script></body></html>"""

    async def parent(_request: web.Request) -> web.Response:
        return web.Response(text=page, content_type="text/html")

    hass.http.app.router.add_get("/_ratgdo_mgmt_panel_test", parent)
    client = await hass_client()
    url = f"http://127.0.0.1:{client.port}/_ratgdo_mgmt_panel_test"
    try:
        await _shot(url, "homekit", "ratgdo for HomeKit", select=None)
        await _shot(url, "esphome", "ESPHome", select="Garage B")
    finally:
        await home_runner.cleanup()
        await esp_runner.cleanup()


async def _shot(url: str, label: str, needle: str, select: str | None) -> None:
    """Open the panel, optionally switch tabs, and check the iframe text."""
    viewports = [("desktop", 1280, 800), ("mobile", 390, 844)]
    for name, width, height in viewports:
        with TemporaryDirectory(ignore_cleanup_errors=True) as profile:
            process = await asyncio.create_subprocess_exec(
                _CHROME,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--remote-debugging-port=0",
                f"--window-size={width},{height}",
                f"--user-data-dir={profile}",
                url,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            assert process.stderr is not None
            debug_port = None
            try:
                while debug_port is None:
                    line = await asyncio.wait_for(process.stderr.readline(), 20)
                    text = line.decode(errors="replace")
                    if "DevTools listening on" in text:
                        debug_port = int(text.split("127.0.0.1:")[1].split("/")[0])
                await _evaluate(
                    debug_port,
                    "Emulation.setDeviceMetricsOverride",
                    {
                        "width": width,
                        "height": height,
                        "deviceScaleFactor": 1,
                        "mobile": name == "mobile",
                    },
                )
                if select:
                    await _evaluate(
                        debug_port,
                        "Runtime.evaluate",
                        {
                            "expression": f"""
                              (() => {{
                                const el = document.querySelector("ratgdo-mgmt-panel");
                                const button = [...el.shadowRoot.querySelectorAll("button")]
                                  .find((item) => item.textContent.includes({json.dumps(select)}));
                                button.click();
                                return true;
                              }})()
                            """,
                            "returnByValue": True,
                        },
                    )
                expression = """
                  (() => {
                    const el = document.querySelector("ratgdo-mgmt-panel");
                    const frame = el && el.shadowRoot && el.shadowRoot.querySelector("iframe");
                    const text = frame && frame.contentDocument && frame.contentDocument.body
                      ? frame.contentDocument.body.innerText : "";
                    const height = frame ? frame.getBoundingClientRect().height : 0;
                    return {text, height};
                  })()
                """
                seen = ""
                height = 0
                for _ in range(40):
                    result = await _evaluate(
                        debug_port,
                        "Runtime.evaluate",
                        {
                            "expression": expression,
                            "returnByValue": True,
                        },
                    )
                    value = (result or {}).get("result", {}).get("value") or {}
                    seen = value.get("text") or ""
                    height = value.get("height") or 0
                    if needle in seen and height >= 240:
                        break
                    await asyncio.sleep(0.25)
                assert needle in seen, seen
                assert height >= 240, height
                if _ARTIFACTS:
                    shot = await _evaluate(
                        debug_port,
                        "Page.captureScreenshot",
                        {"format": "png"},
                    )
                    import base64
                    from pathlib import Path

                    Path(_ARTIFACTS).mkdir(parents=True, exist_ok=True)
                    target = Path(_ARTIFACTS) / f"ratgdo-mgmt-{label}-{name}.png"
                    target.write_bytes(base64.b64decode(shot["data"]))
            finally:
                process.terminate()
                await process.wait()
