import assert from "node:assert/strict";
import test from "node:test";

import { FRAME_SANDBOX, frameHeight, frameMode, fromOwnFrame } from "../frontend/logic.mjs";

test("a controller with no web server does not get an iframe", () => {
  assert.equal(frameMode({ web: false }, "https://ha/proxy", "pending"), "no-web");
  assert.equal(frameMode({ web: true }, "https://ha/proxy", "pending"), "iframe");
  assert.equal(frameMode({ web: true }, null, "pending"), "error");
  assert.equal(frameMode({ web: true }, "https://ha/proxy", "failed"), "error");
  assert.equal(frameMode(null, "https://ha/proxy", "pending"), "empty");
  assert.equal(
    frameMode(
      { web: true, password_required: true, credentials_set: false },
      "https://ha/proxy",
      "pending",
    ),
    "credentials",
  );
  assert.equal(
    frameMode(
      { web: true, password_required: true, credentials_set: true, auth_failed: true },
      "https://ha/proxy",
      "pending",
    ),
    "credentials",
  );
  assert.equal(
    frameMode(
      { web: true, password_required: true, credentials_set: true },
      "https://ha/proxy",
      "pending",
    ),
    "iframe",
  );
});

test("HomeKit firmware shows its own login page", () => {
  for (const extra of [{}, { credentials_set: true, auth_failed: true }]) {
    assert.equal(
      frameMode(
        { firmware: "homekit", web: true, password_required: true, ...extra },
        "https://ha/proxy",
        "pending",
      ),
      "iframe",
    );
  }
  assert.equal(
    frameMode(
      { firmware: "esphome", web: true, password_required: true },
      "https://ha/proxy",
      "pending",
    ),
    "credentials",
  );
});

test("frame height is the viewport minus the frame top, in pixels", () => {
  assert.equal(frameHeight(800, 120), 680);
  assert.equal(frameHeight(300, 200), 240);
  assert.equal(frameHeight(900, 100, 100), 800);
});

test("only a new hass isn't drawn again once the page is up", async () => {
  const { needsDraw } = await import("../frontend/logic.mjs");
  assert.equal(needsDraw(new Map([["hass", {}]]), false), true);
  assert.equal(needsDraw(new Map([["hass", {}]]), true), false);
  assert.equal(needsDraw(new Map([["hass", {}], ["_selected", "a"]]), true), true);
  assert.equal(needsDraw(new Map([["narrow", true]]), true), true);
});

test("Refresh says it is working and explains a failure", async () => {
  const { refreshErrorText, refreshLabel } = await import("../frontend/logic.mjs");
  assert.equal(refreshLabel(false), "Refresh");
  assert.equal(refreshLabel(true), "Refreshing…");
  assert.equal(
    refreshErrorText(new Error("Unauthorized")),
    "Couldn't refresh: Unauthorized",
  );
  assert.equal(
    refreshErrorText({ code: "home_assistant_error", message: " Not set up " }),
    "Couldn't refresh: Not set up",
  );
  assert.match(refreshErrorText(undefined), /^Couldn't refresh\. /);
  assert.match(refreshErrorText({ message: "" }), /^Couldn't refresh\. /);
});

test("Refresh loads the admin page again, not only the details", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../frontend/panel.js", import.meta.url), "utf8");
  const body = source.slice(
    source.indexOf("async _refresh()"),
    source.indexOf("\n  }\n", source.indexOf("async _refresh()")),
  );
  assert.match(body, /callService\("\w+", "refresh"\)/);
  assert.match(body, /catch \(err\)/);
  assert.match(body, /this\._retry\(\)/);
  assert.match(source, /\?disabled=\$\{this\._refreshing\}/);
});

test("the iframe sandbox never shares Home Assistant's origin", () => {
  assert.ok(FRAME_SANDBOX.includes("allow-scripts"));
  assert.ok(!FRAME_SANDBOX.includes("allow-same-origin"));
  assert.ok(!FRAME_SANDBOX.includes("allow-top-navigation"));
});

test("only messages from the panel's own iframe count", () => {
  const frame = {};
  const data = { source: "ratgdo-mgmt-proxy", ok: true };
  assert.equal(fromOwnFrame({ source: frame, data }, frame), true);
  assert.equal(fromOwnFrame({ source: {}, data }, frame), false);
  assert.equal(fromOwnFrame({ source: frame, data: { source: "x" } }, frame), false);
  assert.equal(fromOwnFrame({ source: frame, data }, null), false);
});
