import assert from "node:assert/strict";
import test from "node:test";

import { frameHeight, frameMode } from "../frontend/logic.mjs";

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
