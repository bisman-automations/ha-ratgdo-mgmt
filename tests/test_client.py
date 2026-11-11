"""Identity documents, without a socket."""

from __future__ import annotations

from custom_components.ratgdo_mgmt.client import (
    esphome_web_body,
    homekit_document,
    schemes_to_try,
)
from custom_components.ratgdo_mgmt.const import SCHEME_AUTO, SCHEME_HTTP, SCHEME_HTTPS
from tests.common import STATUS


def test_status_json_shape() -> None:
    """build_status_json is recognized. A random JSON object is not."""
    assert homekit_document(STATUS) is True
    assert homekit_document({"firmwareVersion": "1"}) is False
    assert homekit_document({"gitRepo": "not-ours", "firmwareVersion": "1"}) is False


def test_esphome_web_markers() -> None:
    """web_server.cpp serves /0.js and an HTML page that names ESPHome."""
    assert esphome_web_body(
        "/", "text/html", "<html><script src='/0.js'></script>", 200
    )
    assert esphome_web_body("/0.js", "application/javascript", "var esphome", 200)
    assert not esphome_web_body("/", "text/html", "<html>printer</html>", 200)


def test_auto_tries_http_before_https() -> None:
    """These controllers ship on HTTP."""
    assert schemes_to_try(SCHEME_AUTO) == [SCHEME_HTTP, SCHEME_HTTPS]
    assert schemes_to_try(SCHEME_AUTO, SCHEME_HTTPS) == [SCHEME_HTTPS, SCHEME_HTTP]
    assert schemes_to_try(SCHEME_HTTP) == [SCHEME_HTTP]
