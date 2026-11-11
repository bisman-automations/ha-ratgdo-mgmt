<p align="center">
  <img src="custom_components/ratgdo_mgmt/brand/icon.png" alt="ratgdo Mgmt" width="128">
</p>

# ratgdo Mgmt

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://hacs.xyz/)
[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-2026.10%2B-blue.svg)](https://www.home-assistant.io/)
[![GitHub Release](https://img.shields.io/github/v/release/bisman-automations/ha-ratgdo-mgmt)](https://github.com/bisman-automations/ha-ratgdo-mgmt/releases)
[![Test](https://github.com/bisman-automations/ha-ratgdo-mgmt/actions/workflows/test.yml/badge.svg)](https://github.com/bisman-automations/ha-ratgdo-mgmt/actions/workflows/test.yml)
[![Validate](https://github.com/bisman-automations/ha-ratgdo-mgmt/actions/workflows/validate.yml/badge.svg)](https://github.com/bisman-automations/ha-ratgdo-mgmt/actions/workflows/validate.yml)
[![License](https://img.shields.io/github/license/bisman-automations/ha-ratgdo-mgmt)](LICENSE)

ratgdo Mgmt finds [ratgdo](https://ratgdo.github.io/esphome-ratgdo/) garage door
controllers on your network and opens each one's web page from a sidebar panel.
It covers ratgdo v2.5, ratgdo32, and ratgdo32 disco, on ESPHome firmware or on
HomeKit firmware. Opening, closing, and the light stay on the ESPHome
integration or on HomeKit Controller. This integration is the management page,
the firmware version, and a reboot.

## Requirements

- Home Assistant 2026.10 or newer.
- A ratgdo on the same network, running
  [ESPHome firmware](https://github.com/ratgdo/esphome-ratgdo) or
  [HomeKit firmware](https://github.com/ratgdo/homekit-ratgdo)
  ([ESP32 build](https://github.com/ratgdo/homekit-ratgdo32)).

## Installation

ratgdo Mgmt is not in the default catalog yet. Add this repository, then install it.

### Marketplace (Home Assistant 2026.11 and newer)

[![Open your Home Assistant instance and open this repository in the Marketplace.](https://my.home-assistant.io/badges/marketplace_repository.svg)](https://my.home-assistant.io/redirect/marketplace_repository/?owner=bisman-automations&repository=ha-ratgdo-mgmt&category=integration)

1. Select the button above, or go to **Settings > Marketplace**, choose **Add
   from link**, enter `bisman-automations/ha-ratgdo-mgmt` under **GitHub link**, and
   select **Add**. Adding a repository from a link needs a GitHub connection;
   the Marketplace asks you to connect one if you haven't.
2. Install **ratgdo Mgmt**. If a repair asks you to restart Home Assistant, restart it.

New versions show up under **Settings > Updates**. Already installed ratgdo Mgmt with
HACS? There's nothing to do: Home Assistant moves it into the Marketplace the
first time it starts on 2026.11.

### HACS (Home Assistant 2026.10 and older)

[![Open your Home Assistant instance and open this repository in HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=bisman-automations&repository=ha-ratgdo-mgmt&category=integration)

ratgdo Mgmt does not appear in search until it is in the default catalog. Add it as a custom repository, then download it:

1. In HACS open the menu, choose **Custom repositories**, and add `https://github.com/bisman-automations/ha-ratgdo-mgmt` as an **Integration**.
2. Download **ratgdo Mgmt** and restart Home Assistant.

### Custom repository

ratgdo Mgmt is not in the default catalog yet. The repository to add, in the
Marketplace or in HACS, is:

`https://github.com/bisman-automations/ha-ratgdo-mgmt`

Add that as an integration repository, then install **ratgdo Mgmt** from the
list. The Marketplace button and the HACS button above open the same
repository.

### Manual

1. Download `ratgdo_mgmt.zip` from the [latest release](https://github.com/bisman-automations/ha-ratgdo-mgmt/releases/latest).
2. Unzip it into `config/custom_components/ratgdo_mgmt/` and restart Home Assistant.

## Setup

[![Open your Home Assistant instance and start setting up ratgdo Mgmt.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=ratgdo_mgmt)

Select the button above, or go to **Settings > Devices & services > Add
integration** and search for **ratgdo Mgmt**.

Home Assistant also offers to set it up when it hears a ratgdo on the
network. One entry covers every controller. Further controllers are added on
their own.

If a controller is not discovered, open the integration's options and choose
**Add a controller**. Type the address. Leave **Protocol** on
**Detect automatically** unless you know it: that tries HTTP first, then
HTTPS, on port 80 (or whatever you set as the ESPHome web server port).
Leave **Verify SSL certificate** off. These controllers ship on plain HTTP.
Turn **Verify SSL certificate** on only for a certificate signed by an
authority Home Assistant already trusts. If you did put HTTPS in front of
one, ratgdo Mgmt shows that certificate's SHA-256 fingerprint and remembers
it.

**Web username** and **Web password** are optional. HomeKit firmware's page
uses them when **Require password** is on. The default until you change it
is `admin` / `password`. ESPHome's stock page has no password. Saving the
password lets the sidebar open settings without asking again. Leave it
blank and the page's own password box still works.

If the certificate changes, Home Assistant raises a repair named for the
controller. Open the repair, compare the new fingerprint, and accept it
only if you expected the change.

### Sidebar

**ratgdo Mgmt** is in the sidebar for administrators. Each controller is a
tab with its name, address, firmware, version, whether it is online, and
when it was last seen, plus **Open in new tab**.

The web page is loaded through Home Assistant, not straight from the
controller. That is what lets the tab show a plain HTTP controller while
Home Assistant itself is open over HTTPS. Only an administrator can open
the proxied page. **Open in new tab** uses the same proxied address.

If the page does not load, the tab says so instead of leaving a blank area.
**Retry** asks again. **Open controller directly** is the controller's own
address.

An ESPHome controller built without `web_server:` has no page to embed.
The tab says so and lists the project name, version, board, and MAC that
were discovered. Door controls for that controller stay on the ESPHome
device.

### Entities

Each controller gets a device, plus:

- **Connectivity** and **Last seen**
- **Firmware** (ESPHome or HomeKit), **Firmware version**, and **Board**
- **Firmware** update, with a link to the matching GitHub release
- **Reboot**

HomeKit firmware also gets **Password required**, **Uptime**, **Free
heap**, and **Crash count**. Those come from the controller's status page.
They are not the door, the light, or the lock.

When the same controller is also set up through ESPHome or HomeKit
Controller, ratgdo Mgmt stores the same MAC address and links its device
to that one.

**Reboot** on HomeKit firmware calls the controller's reboot route, which
does not need the web password. On ESPHome it presses the web server's
Restart button, which exists only when `web_server:` is enabled. The
ESPHome integration's own Restart button is the one to use when the web
server is off.

The update entity compares a HomeKit version such as 2.2.6 with the newest
release of that firmware. ESPHome's version on the device is the board
profile from the YAML (2.5, 32disco, 2.0). The esphome-ratgdo releases use
a different number, so the entity links the release notes and does not
call the board profile out of date because of that number.

### Ignoring a controller

In the integration's options, choose **Manage controllers**. **Ignore**
hides a controller and keeps it hidden if it is discovered again. **Show
again** brings it back. **Remove** forgets it, so a later discovery can add
it again.

## Troubleshooting

- **Nothing is discovered.** The controller and Home Assistant need to be
  on the same network. ESPHome firmware is found from its mDNS
  advertisement (`project_name` starting with `ratgdo.`). HomeKit firmware
  is found from its own `_ratgdo` advertisement. You can also add it by
  address.
- **ESPHome, and the tab says there is no web page.** The build was
  compiled without `web_server:`. Add that block and update the device
  from the ESPHome dashboard if you want the page. The controller is still
  listed.
- **The tab says it can't load the web page.** Choose **Retry**. If that
  still fails, use **Open controller directly**.
- **HomeKit settings ask for a password.** The default is `admin` /
  `password` until you change it on the controller. You can save that
  password in the integration's options so the sidebar does not ask.
  A repair appears when a saved password is rejected.
- **Certificate changed.** A repair named for the controller means the
  certificate no longer matches the one ratgdo Mgmt pinned. Accept the new
  fingerprint from the repair only if you expected it to change.
- **Diagnostics:** on the integration's page, open the menu and choose
  **Download diagnostics**. The web password and the HomeKit setup code
  are removed. Attach the file to an issue (check it first for anything
  you'd rather not share).
- **Debug logs:** on the integration's page choose **Enable debug logging**,
  reproduce the problem, then **Disable debug logging** to download the log.
- Report problems at [Issues](https://github.com/bisman-automations/ha-ratgdo-mgmt/issues).

## Development

```
python3.14 -m venv .venv && . .venv/bin/activate
pip install -r requirements_test.txt
ruff check . && ruff format --check .
pytest
```

The sidebar panel is built with `npm run build` from `frontend/panel.js`.
`node --test tests/*.mjs` checks the frame rules.

CI also tests the oldest supported Home Assistant (`requirements_test_min.txt`)
and runs hassfest and the HACS checks. Releases are drafted automatically from
`CHANGELOG.md` on every push to `main` and published by hand. See
[CLAUDE.md](CLAUDE.md) and [CONTRIBUTING](https://github.com/bisman-automations/.github/blob/main/CONTRIBUTING.md).

## License

[MIT](LICENSE)
