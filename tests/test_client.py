"""Identity documents, without a socket."""

from __future__ import annotations

from custom_components.ratgdo_mgmt.client import (
    esphome_web_body,
    homekit_document,
    restart_path_from_events,
    schemes_to_try,
    www_authenticate_scheme,
)
from custom_components.ratgdo_mgmt.const import SCHEME_AUTO, SCHEME_HTTP, SCHEME_HTTPS
from tests.common import STATUS


def test_status_json_shape() -> None:
    """build_status_json is recognized. A random JSON object is not."""
    assert homekit_document(STATUS) is True
    assert homekit_document({"firmwareVersion": "1"}) is False
    assert homekit_document({"gitRepo": "not-ours", "firmwareVersion": "1"}) is False


def test_esphome_web_markers() -> None:
    """Versions 1, 2, and 3, including a local bundle, are the web UI.

    A 401 is not decided from the body. ``www_authenticate_scheme`` is.
    ``/0.js`` is only the optional js_include file.
    """
    assert esphome_web_body(
        "/", "text/html", "<html><script src='/0.js'></script>", 200
    )
    assert esphome_web_body(
        "/",
        "text/html",
        "<html><esp-app></esp-app><script src='https://oi.esphome.io/v3/www.js'></script>",
        200,
    )
    assert esphome_web_body(
        "/",
        "text/html",
        "<html><script src='https://oi.esphome.io/v2/www.js'></script>",
        200,
    )
    assert esphome_web_body(
        "/",
        "text/html",
        "<html><script src='https://oi.esphome.io/v1/webserver-v1.min.js'></script>",
        200,
    )
    assert esphome_web_body("/0.js", "application/javascript", "var esphome", 200)
    assert not esphome_web_body("/", "text/html", "<html>printer</html>", 200)
    assert not esphome_web_body("/", "text/html", "Unauthorized", 401)
    assert www_authenticate_scheme('Basic realm="Login Required"') == "basic"
    assert (
        www_authenticate_scheme('Digest realm="Login Required", nonce="abc"')
        == "digest"
    )
    assert www_authenticate_scheme(None) is None


def test_restart_path_comes_from_the_events_name() -> None:
    """2026.x ids use the entity name, not the old object id."""
    text = (
        "event: state_detail_all\n"
        'data: {"id":"button/Restart","name":"Restart","domain":"button"}\n\n'
        "event: state\n"
        'data: {"id":"switch/Light","name":"Light","domain":"switch"}\n\n'
    )
    assert restart_path_from_events(text) == "/button/Restart/press"
    assert restart_path_from_events("data: not-json\n") is None


def test_auto_tries_http_before_https() -> None:
    """These controllers ship on HTTP."""
    assert schemes_to_try(SCHEME_AUTO) == [SCHEME_HTTP, SCHEME_HTTPS]
    assert schemes_to_try(SCHEME_AUTO, SCHEME_HTTPS) == [SCHEME_HTTPS, SCHEME_HTTP]
    assert schemes_to_try(SCHEME_HTTP) == [SCHEME_HTTP]
