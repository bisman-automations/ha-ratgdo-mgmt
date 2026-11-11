"""Constants for ratgdo Mgmt.

Discovery and the web API follow the firmware, not guesses:

- ESPHome firmware is the packages in ``ratgdo/esphome-ratgdo``. Every
  board YAML sets ``project.name`` to ``ratgdo.<board>`` (for example
  ``ratgdo.v25board_esp32_secplus2``, ``ratgdo.v32disco_secplus2``) and
  ``name_add_mac_suffix: true``. ESPHome core announces that on
  ``_esphomelib._tcp`` (``esphome/components/mdns``), with TXT
  ``project_name``, ``project_version``, ``friendly_name``, ``mac``, and
  ``version``. The service port is the native API (6053), not the web
  server. ``web_server:`` is in the stock YAML and listens on port 80
  unless changed; a build that drops ``web_server`` has no page.
- HomeKit firmware is ``ratgdo/homekit-ratgdo`` (ESP8266,
  ``MODEL_NAME`` ``ratgdo_v2.5``) and ``ratgdo/homekit-ratgdo32``
  (ESP32, ``MODEL_NAME`` ``ratgdo_32``, disco builds add a
  ``distanceSensor`` field). ``src/web.cpp`` registers ``_http._tcp``
  and ``_ratgdo._tcp`` on port 80. TXT on ``_ratgdo`` includes
  ``model``, ``firmwareVersion``, ``deviceName``, ``gitRepo``,
  ``macAddress``, and ``passwordRequired``. HomeSpan also announces
  ``_hap._tcp`` with model ``ratgdo-ESP32``.
- The web UI's password hash is ``MD5(username + ":" + realm + ":" +
  password)`` with realm ``RATGDO Login Required`` (``functions.js``
  ``www_realm``, ``utilities.cpp`` ``www_realm``). The default
  ``admin`` / ``password`` hash in ``config.cpp`` matches that realm.
  The page sends it as ``X-API-Key``. ``/status.json`` and ``POST
  /reboot`` do not require it. ``/auth``, ``/setgdo``, ``/reset``,
  logs, and ``/update`` do (``requestAuthenticated``).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "ratgdo_mgmt"
ESPHOME_DOMAIN: Final = "esphome"
HOMEKIT_DOMAIN: Final = "homekit_controller"

PANEL_TITLE: Final = "ratgdo Mgmt"
PANEL_URL: Final = "ratgdo-mgmt"
PANEL_ICON: Final = "mdi:garage"
PANEL_JS_URL: Final = f"/{DOMAIN}/ratgdo-mgmt-panel.js"
PANEL_ELEMENT: Final = "ratgdo-mgmt-panel"

SIGNAL_DEVICES_UPDATED: Final = f"{DOMAIN}_devices_updated"

# ESPHome core (mdns_component.cpp SERVICE_ESPHOMELIB). _esphome._tcp is not
# what current ESPHome sends; it is accepted so a future rename still matches.
ESPHOME_SERVICE: Final = "_esphomelib._tcp.local."
ESPHOME_SERVICE_ALT: Final = "_esphome._tcp.local."
# web.cpp MDNS.addService("ratgdo", "tcp", 80) and ("http", "tcp", 80).
RATGDO_SERVICE: Final = "_ratgdo._tcp.local."
HTTP_SERVICE: Final = "_http._tcp.local."
# HomeKit accessory advertisement. HomeSpan's model argument is ratgdo-ESP32.
HAP_SERVICE: Final = "_hap._tcp.local."

# esphome-ratgdo YAML ``project.name``.
PROJECT_PREFIX: Final = "ratgdo."
# HomeKit gitRepo values compiled into web.cpp (_GITREPO).
GIT_REPO_ESP8266: Final = "homekit-ratgdo"
GIT_REPO_ESP32: Final = "homekit-ratgdo32"
HOMEKIT_REPOS: Final = frozenset({GIT_REPO_ESP8266, GIT_REPO_ESP32})
ESPHOME_GITHUB_REPO: Final = "esphome-ratgdo"
GITHUB_OWNER: Final = "ratgdo"

# functions.js www_realm and utilities.cpp www_realm. The comment in
# config.cpp that says the default hash is "admin:ratgdo:password" does not
# match the bytes in that file; MD5("admin:RATGDO Login Required:password")
# is 10d3c00fa1e09696601ef113b99f8a87, which is the shipped default.
AUTH_REALM: Final = "RATGDO Login Required"
DEFAULT_USERNAME: Final = "admin"

# web_server default port (esphome web_server DEFAULT_PORT) and the port
# homekit web.cpp binds. The ESPHome API port is not an HTTP port.
DEFAULT_PORT: Final = 80
ESPHOME_API_PORT: Final = 6053

STATUS_PATH: Final = "/status.json"
AUTH_PATH: Final = "/auth"
REBOOT_PATH: Final = "/reboot"
# Pre-2026 web_server used the object id. 2026.x matches the entity name
# from /events (stock base.yaml names the button "Restart"), so the path
# is learned at runtime and this constant is only the old shape.
ESPHOME_RESTART_PATH: Final = "/button/restart/press"
# esphome web_server.cpp serves the local UI's script at this path.
ESPHOME_JS_PATH: Final = "/0.js"
HEALTHCHECK_PATH: Final = "/healthcheck"

FIRMWARE_ESPHOME: Final = "esphome"
FIRMWARE_HOMEKIT: Final = "homekit"
FIRMWARES: Final = (FIRMWARE_ESPHOME, FIRMWARE_HOMEKIT)

BOARD_V2: Final = "ratgdo_v2"
BOARD_25: Final = "ratgdo25"
BOARD_32: Final = "ratgdo32"
BOARD_DISCO: Final = "ratgdo32_disco"
BOARD_UNKNOWN: Final = "ratgdo"
BOARDS: Final = (BOARD_V2, BOARD_25, BOARD_32, BOARD_DISCO, BOARD_UNKNOWN)

PROBE_TIMEOUT: Final = 5.0
UPDATE_INTERVAL: Final = timedelta(seconds=30)
# GitHub release checks are not part of the device poll.
RELEASE_INTERVAL: Final = timedelta(hours=6)
FRAME_LOAD_TIMEOUT_MS: Final = 8000
# Floor for the pixel height. A short window still shows the embedded page.
FRAME_MIN_HEIGHT_PX: Final = 240

ATTR_CERT_SHA256: Final = "cert_sha256"
SIGNED_PATH_SECONDS: Final = 300
PROXY_COOKIE: Final = "ratgdo_mgmt_proxy"
PROXY_HOOK: Final = "__ratgdo_mgmt__/hook.js"
PROXY_SOURCE: Final = "ratgdo-mgmt-proxy"

SCHEME_AUTO: Final = "auto"
SCHEME_HTTP: Final = "http"
SCHEME_HTTPS: Final = "https"
SCHEMES: Final = (SCHEME_AUTO, SCHEME_HTTP, SCHEME_HTTPS)

CONF_SCHEME: Final = "scheme"
CONF_VERIFY_SSL: Final = "verify_ssl"
CONF_DEVICE_ID: Final = "device_id"
CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"

WS_SIGN_PROXY: Final = "ratgdo_mgmt/sign_proxy"

ATTR_MAC: Final = "mac"
ATTR_NODE_NAME: Final = "node_name"
ATTR_LINK_URL: Final = "link_url"
ATTR_SCHEME_MODE: Final = "scheme_mode"
ATTR_IGNORED: Final = "ignored"
ATTR_SOURCE: Final = "source"
ATTR_FIRMWARE: Final = "firmware"
ATTR_FIRMWARE_VERSION: Final = "firmware_version"
ATTR_ESPHOME_VERSION: Final = "esphome_version"
ATTR_PROJECT_NAME: Final = "project_name"
ATTR_PROJECT_VERSION: Final = "project_version"
ATTR_GIT_REPO: Final = "git_repo"
ATTR_MODEL: Final = "model"
ATTR_BOARD: Final = "board"
ATTR_WEB: Final = "web"
ATTR_PASSWORD_REQUIRED: Final = "password_required"
ATTR_RESTART_PATH: Final = "restart_path"
ATTR_API_PORT: Final = "api_port"

SERVICE_REFRESH: Final = "refresh"
SERVICE_IGNORE: Final = "ignore_device"
SERVICE_REMOVE: Final = "remove_device"
SERVICE_REBOOT: Final = "reboot"

# Hostnames the stock firmware uses. ESPHome name_add_mac_suffix produces
# ratgdov25-aabbcc and ratgdo32disco-aabbcc. HomeKit make_rfc952 turns
# "Garage Door ABCDEF" into "Garage-Door-ABCDEF". The manifest patterns are
# lowercase because hassfest requires that. Matching in discovery lowercases
# the hostname, so a mixed-case lease still counts once the flow is started.
