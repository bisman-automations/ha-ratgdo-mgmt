# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-11-27

### Changed

- **The ratgdo Mgmt page opens faster.** Your browser now keeps the page's script instead of downloading it again every time you open it. After an update it loads the new one.

## [0.2.1] - 2026-11-27

### Fixed

- **What ratgdo Mgmt learns about a controller is kept after a restart.** Changes found while checking a controller (a new firmware version, its name, the certificate it was trusted with, the Restart button's address) were often only kept in memory, and Home Assistant didn't save them. After a restart ratgdo Mgmt went back to older details, and could trust a controller's certificate again without asking. Every change is now saved, including after you fix a password or certificate in **Repairs**.

## [0.2.0] - 2026-11-27

### Security

- **The controller's page is kept apart from Home Assistant.** The web page shown in the panel ran as part of Home Assistant, so anything on a controller's page (including ESPHome's page script, which loads from the internet), or a device on your network pretending to be a ratgdo, could have used your Home Assistant login. It now runs in a sandbox, in the panel and anywhere else it's opened: it can't see your Home Assistant login or storage, and it can't do anything in Home Assistant as you.
- **ratgdo Mgmt signs its links with a key of its own.** It used to borrow the key Home Assistant uses for its own temporary links. It now keeps a random key in its own storage and leaves Home Assistant's alone.

### Changed

- **Open controller directly** replaces **Open in new tab**. It opens the controller's own address on your home network instead of the page through Home Assistant.
- The panel's link to a controller now works for 12 hours. Opening the controller again, or **Retry**, gets a new one.

### Fixed

- A controller page that opens a websocket through ratgdo Mgmt no longer fails straight away.

## [0.1.7] - 2026-11-22

### Changed

- **Less checking when other devices change.** ratgdo Mgmt looked through Home Assistant's device list, and checked every controller over the network again, whenever any device in your home changed, even a lamp being renamed. It now looks again only when an ESPHome or HomeKit device that looks like a ratgdo is added, or its address, name or model changes. Several changes in a row lead to one more look, not one per change.

### Fixed

- **Nothing keeps running after ratgdo Mgmt is unloaded.** A look through the device list, or a controller just found on the network, could still be checked after the integration was reloaded or removed. That work now stops with it.

## [0.1.6] - 2026-11-21

### Changed

- **Ruff 0.17.6.** Linting uses the current Ruff release. Nothing changes for you.

## [0.1.5] - 2026-11-20

### Fixed

- **Refresh does what it says.** Refresh only checked each controller again in the background, so the page in the panel stayed as it was and the button seemed to do nothing. It now also loads the controller's page again, including after a "Can't load the web page" message. The button reads **Refreshing…** while it works, and if Home Assistant refuses or fails, the panel says why instead of nothing happening.

## [0.1.4] - 2026-11-15

### Changed

- **A lighter panel.** The sidebar panel used to draw itself again (and measure the page) on every change anywhere in Home Assistant, although it shows none of them. It now draws only when something on it changes.

## [0.1.3] - 2026-11-13

### Fixed

- **HomeKit firmware opens its own page again.** A ratgdo running the HomeKit firmware with a web password showed a form asking for an ESPHome web server password. Its page now opens in the panel and shows its own login, as it does in a browser. ESPHome controllers with a web server password still get the form.

## [0.1.2] - 2026-11-13

### Fixed

- **ratgdo Mgmt has its own icon.** It was showing a tablet; it now shows a garage door, at the sizes Home Assistant expects, with a version for dark mode.

## [0.1.1] - 2026-11-13

### Changed

- **One restart at a time.** A controller's Restart button sends one command at a time; the other entities tell Home Assistant they can update together, as Home Assistant recommends.

## [0.1.0] - 2026-11-11

### Added

- Discover ratgdo controllers running ESPHome firmware or HomeKit firmware
  (ratgdo v2.5, ratgdo32, and ratgdo32 disco) from mDNS, DHCP, HomeKit, and
  devices already in Home Assistant, and add one by address.
- An administrator sidebar, ratgdo Mgmt, with one tab per controller. The
  tab loads that controller's own web page through Home Assistant. An
  ESPHome build without a web server explains that and shows the identity
  that was discovered.
- Firmware, firmware version, board, connectivity, and last seen for each
  controller. HomeKit firmware also reports whether a web password is
  required, uptime, free heap, and the crash count. A reboot button uses
  the HomeKit reboot route, or the ESPHome web server's Restart button
  when that page exists.
- A firmware update entity. HomeKit versions are compared with the newest
  GitHub release of the matching firmware. The release notes link is on
  the entity. ESPHome's board profile is not the same number as the
  esphome-ratgdo build tag, so that release is linked without being
  treated as a newer board profile.
- Options to add a controller by address, choose HTTP or HTTPS, pin a
  certificate, and save the web username and password. Ignore or remove a
  controller. An ignored controller stays hidden when it is discovered again.
- A repair when a saved web password is rejected, and a repair when a
  pinned certificate changes.

### Fixed

- An ESPHome ratgdo whose `web_server` has `auth:` (HTTP Basic by default
  in ESPHome 2026.10, or Digest) was shown as having no web page. `GET /`
  returning 401 with `WWW-Authenticate` means the page is there. The
  sidebar asks for that username and password, the proxy answers Basic
  and Digest, and `local: true` plus web server versions 1, 2, and 3 are
  shown, including `/events` and the name-based action URLs. Reboot
  learns the Restart button from the `/events` list instead of assuming
  `/button/restart/press`.

[0.2.2]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bisman-automations/ha-ratgdo-mgmt/releases/tag/v0.1.0
