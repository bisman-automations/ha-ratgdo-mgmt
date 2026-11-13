# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.3]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/bisman-automations/ha-ratgdo-mgmt/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bisman-automations/ha-ratgdo-mgmt/releases/tag/v0.1.0
