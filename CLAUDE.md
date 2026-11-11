# ratgdo Mgmt: notes for Claude and other coding agents

Home Assistant custom integration (`ratgdo_mgmt`), installed through the
Marketplace on Home Assistant 2026.11 and newer and through HACS on 2026.10.
It finds ratgdo garage-door controllers on the LAN and opens each one's web
page from an admin-only sidebar panel. Read this before changing anything.

## Layout

- `custom_components/ratgdo_mgmt/`: the integration.
  - `__init__.py`: setup, unload, admin-only services.
  - `config_flow.py`: the single config entry, zeroconf, DHCP, HomeKit,
    manual host, options, and reconfigure.
  - `client.py`: probes `/status.json` and the ESPHome web server.
  - `auth.py`: HomeKit `X-API-Key` and Digest for the upstream path.
  - `tls.py`: leaf SHA-256 pinning and the aiohttp fingerprint check.
  - `proxy.py`: admin-only reverse proxy used by the sidebar iframe.
  - `repairs.py`: accept a changed certificate, or replace a rejected password.
  - `discovery.py`: zeroconf, DHCP, and device-registry matching.
  - `coordinator.py`: polling, device registry, releases, repairs.
  - `releases.py`: GitHub release lookup and version comparison.
  - `binary_sensor.py`, `button.py`, `sensor.py`, `update.py`: entities.
  - `panel.py`: admin sidebar panel and the static panel script.
  - `websocket_api.py`: admin-only live device list.
  - `diagnostics.py`: config-entry diagnostics.
  - `frontend/ratgdo-mgmt-panel.js`: the built Lit panel (source in
    `frontend/` at the repo root; `npm run build` refreshes it).
- `frontend/`: panel source. `logic.mjs` is the part the Node tests import.
- `tests/`: pytest, plus `tests/panel.test.mjs`.
- `README.md` is user documentation; `CHANGELOG.md` is the release history.

## Checks

The shared checks below. Also `node --test tests/*.mjs` for the panel
rules, and `npm run build` after changing `frontend/`. There is no mypy
job. Hassfest is `python -m script.hassfest --integration-path
custom_components/ratgdo_mgmt` from a Home Assistant core checkout of the
version under test (hassfest is not installed with the test harness).

## Conventions

Discovery follows the firmware source, not guesses. The trees this was
written against are `ratgdo/esphome-ratgdo`, `ratgdo/homekit-ratgdo`, and
`ratgdo/homekit-ratgdo32` on their default branches.

- ESPHome core announces `_esphomelib._tcp` (`mdns_component.cpp`,
  `SERVICE_ESPHOMELIB`). It does not announce `_esphome._tcp`. This
  integration listens for both. TXT `project_name` is `ratgdo.<board>`
  in every stock YAML (`ratgdo.v25board_esp32_secplus2`,
  `ratgdo.v32disco_secplus2`, `ratgdo.v2board_esp8266_d1_mini`, ...).
  The service port is the native API (6053), not the web server.
  `web_server:` is in the stock YAML (port 80). A build that drops it
  has no page; the node is still managed from the advertisement.
- HomeKit firmware (`src/web.cpp`) adds `_http._tcp` and `_ratgdo._tcp`
  on port 80. TXT on `_ratgdo` includes `model`, `firmwareVersion`,
  `deviceName`, `gitRepo`, `macAddress`, and `passwordRequired`.
  `gitRepo` is `homekit-ratgdo` (ESP8266, model `ratgdo_v2.5`) or
  `homekit-ratgdo32` (ESP32, model `ratgdo_32`). Disco builds are the
  only ones that emit `distanceSensor`. HomeSpan also announces
  `_hap._tcp` with model `ratgdo-ESP32`. The HAP port is not the web port.
- `GET /status.json` is unauthenticated (`handle_status`). It is a
  HomeKit document when `gitRepo` is one of those two names and
  `firmwareVersion` is set. `POST /reboot` is unauthenticated
  (`handle_reboot`). `GET /auth`, `POST /setgdo`, `POST /reset`, the
  logs, and `POST /update` call `requestAuthenticated`.
- The web password hash is MD5 of `username:RATGDO Login Required:password`
  (`functions.js` `www_realm`, `utilities.cpp`). The page sends it as
  `X-API-Key`. The default `admin` / `password` matches the hash shipped
  in `config.cpp` (`10d3c00fa1e09696601ef113b99f8a87`). The comment next
  to that hash says the realm is `ratgdo`; the bytes do not.
- ESPHome `web_server.cpp` serves `/`, `/0.js`, `/0.css`, and `/events`,
  and `POST /button/<object id>/press`. The stock Restart button's
  object id is `restart` (`base.yaml` name "Restart"). Stock YAML does
  not set `web_server` auth. When someone does, it is basic (the
  default) or digest.
- This integration never reads or writes ESPHome or HomeKit Controller
  `runtime_data` or another integration's config entry data. Device
  registry entries are read-only input. Our own device is registered
  with the same MAC connection. Home Assistant 2026.10 does not merge
  two config entries onto one device by MAC, so `via_device_id` on our
  device points at the ESPHome or HomeKit Controller device.

One config entry holds every controller under `options["devices"]`. The
stable id is the MAC when one is known, otherwise an id minted for a
manual host. Ignored controllers stay in options so discovery does not
add them back.

Scheme `auto` tries HTTP, then HTTPS, and remembers which one answered.
`verify_ssl` off (the default) pins the leaf certificate when the page
is HTTPS. `verify_ssl` on uses Home Assistant's verifying session. A
stored pin that no longer matches raises a repair.

The panel does not embed the controller directly. The iframe loads
`/api/ratgdo_mgmt/proxy/{entry_id}/{device_id}/` with a short-lived
signed path. That response sets an HttpOnly cookie. The proxy never
forwards Home Assistant's bearer token. It forwards `X-API-Key`, fills
that header from the saved password when the page did not send one, and
answers a Digest or Basic challenge for the upstream path (a browser
prompt would hash the proxy path, which the firmware rejects). HomeKit
static files are gzip; the proxy decompresses them before rewriting
URLs. The iframe height is measured in pixels because the custom panel
host has no definite height. An ESPHome node with no web server gets a
message and the identity that mDNS provided, not a blank frame.

Door, light, lock, and obstruction entities are not created. Those
belong to the ESPHome integration and to HomeKit Controller.

## Open decisions

- ESPHome `project_version` (`2.5`, `32disco`, `2.0`) is not the
  `esphome-ratgdo` GitHub tag (`v1635` and similar). The update entity
  links that release and only marks an update when the two strings are
  the same kind of version. HomeKit versions do compare.
- A headless ESPHome node (no `web_server`, and no mDNS) cannot be added
  by host. The native API is not spoken here.
- The ESP8266 HomeKit model string is always `ratgdo_v2.5`, including
  boards that are not a v2.5. The v2 versus v2.5 split is reliable from
  the ESPHome project name, not from that model string.
- `POST /button/restart/press` assumes the stock object id `restart`. A
  renamed Restart button will not be found.
- Real hardware has not been on the bench for this release. mDNS TXT
  key casing, the ESP8266 `_hap._tcp` model, and a changed ESPHome web
  port are the pieces most likely to need a capture from a live device.

<!-- BEGIN bisman-automations shared rules -->
<!-- This block is the same in every bisman-automations repo. Edit it in
     bisman-automations/.github (templates/CLAUDE.shared.md) and copy it to
     every repo; the Validate workflow's "standards" job checks it matches. -->

## Shared rules (every bisman-automations repo)

### Releases

- The version lives in `custom_components/<domain>/manifest.json`. Anything
  else that repeats it is called out in the repo-specific notes below and is
  bumped in the same commit.
- Versions follow [Semantic Versioning](https://semver.org): patch for fixes,
  translations, docs and CI; minor for new features, options or entities;
  major when something users rely on is removed or renamed (entities,
  services, events, options) or setup has to be redone.
- Check what is released before choosing a version:
  `git ls-remote --tags origin | awk -F/ '{print $3}' | sort -V | tail -1`
  (`sort -V`: plain sorting puts `v1.10.0` before `v1.9.0`). Never add
  changes to a released version. If the manifest version has no tag yet,
  add to its CHANGELOG section instead of bumping again.
- Every push to `main` ships as a release. In that same commit, named
  `Release X.Y.Z`, bump the manifest version and write the notes directly
  under a new `## [X.Y.Z] - YYYY-MM-DD` heading in `CHANGELOG.md` (Keep a
  Changelog: Added, Changed, Deprecated, Removed, Fixed, Security), with
  that version's compare link at the bottom. There is no `## [Unreleased]`
  section and no `[Unreleased]:` compare link. New work is not collected
  under a holding heading and moved later; the release commit is where the
  heading and the entries are written. The standards check fails if a
  `## [Unreleased]` heading is present.
- Ask Donavan before every push. Push fast-forward only: never force-push,
  rebase or amend anything already pushed, or rewrite history in any other
  way. Rewriting history orphans the release tags (it broke drafting in
  ha-button-actions).
- Pushing to `main` runs **Draft release**, which creates or refreshes a
  draft `vX.Y.Z` with that version's CHANGELOG section as the notes, the
  commits since the last release and `<domain>.zip`. **Donavan publishes
  the draft himself**, and publishing creates the tag. Never create or push
  tags, publish releases, or edit published releases.
- Publishing runs **Release check**: the tag must match the manifest version
  and the CHANGELOG, and be on `main`. If it fails, fix it with a new patch
  release, not by moving the tag.

### Commits

- Author commits as `Donavan Becker <donavan.becker@icloud.com>` (set
  `git config user.name` / `user.email` in the clone). HACS's
  default-repository check needs the submitter to have a fair share of the
  commits. Credit an AI assistant with a `Co-Authored-By:` trailer if you
  like, never as the author.
- Subject lines are plain, imperative and say what changed for the user
  ("Show Pico remotes as unavailable when Lutron isn't running"). No
  `fix:`/`feat:` prefixes. Release commits are "Release X.Y.Z".
- Commit and push only when asked.

### CI (shared workflows)

- `.github/workflows/` holds four thin callers of the reusable workflows in
  [bisman-automations/.github](https://github.com/bisman-automations/.github):
  `test.yml` (lint, frontend, pytest on the oldest supported and the newest
  Home Assistant, plus the upcoming one as information only), `validate.yml`
  (hassfest, HACS, standards), `draft-release.yml` and `release-check.yml`.
  Don't add jobs to the callers. Use the shared workflow's inputs, or change
  the shared workflow so every repo gets the improvement.
- `requirements_test.txt` leaves `pytest-homeassistant-custom-component`
  unpinned (newest Home Assistant) and pins ruff (and mypy where used).
  `requirements_test_min.txt` pins the harness release for the minimum in
  `hacs.json`: the newest harness release of that month. CI fails if they
  drift apart.
- Raising the minimum Home Assistant means changing, together: `hacs.json`,
  `requirements_test_min.txt`, `python-min` in `test.yml` (3.13 up to
  2026.2, 3.14 from 2026.3), the README's Home Assistant badge, and a
  CHANGELOG entry.
- Home Assistant 2026.3 and newer need Python 3.14 (3.14.2+).
- The published hassfest rejects `categories` in `manifest.json` and Pillow
  in `requirements`. Leave both out.
- Dependabot (`.github/dependabot.yml`) proposes action and pinned-tool
  updates weekly. It ignores the test harness on purpose.
- Test and Validate also run every Thursday, the day after Home Assistant's
  betas come out. The **next** test job (newest pre-release harness) is
  information only: when it fails, fix the cause before that release ships.

### Before saying work is done

Run from the repo root, in a Python 3.14 venv with `requirements_test.txt`
installed:

```
ruff check .
ruff format --check .
pytest
```

Also run `node --test tests/*.mjs` when the repo has Node tests, mypy when
the repo-specific notes list it, and the tests in a second venv with
`requirements_test_min.txt` when a change could behave differently on the
oldest supported Home Assistant. The standards check (also in CI) is
`python <path to bisman-automations/.github>/scripts/check_repo.py .`.

### Code and docs

- Support every Home Assistant from the `hacs.json` minimum to the newest
  release. Check for deprecations in the newest release and the beta.
- Keep entity IDs, unique IDs, service names and event names stable. When
  one has to change, migrate it and say so under Changed in the CHANGELOG.
- `strings.json` and `translations/en.json` hold the same keys. Home
  Assistant reads only `translations/`, so change both in the same commit.
- Never put personal details in the repo (README, CHANGELOG, code, tests,
  screenshots): no names, addresses, account or device identifiers, or real
  entity IDs. Use placeholders such as `light.living_room`.
- `README.md` is user documentation with the standard header (badges, HACS
  and "add integration" My buttons) and sections Installation, Setup, ...,
  Troubleshooting, Development, License. Use plain language and show names,
  not entity IDs, wherever the UI does.
<!-- END bisman-automations shared rules -->
