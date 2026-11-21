/**
 * How the sidebar panel decides what to show for one ratgdo.
 *
 * The web page is loaded through Home Assistant's proxy, so the browser
 * talks to Home Assistant and never has to trust a certificate or mix a
 * plain HTTP controller into an HTTPS Home Assistant page.
 *
 * Home Assistant's custom panel host does not give this element a
 * definite height, so a percentage or flex-grow iframe collapses. The
 * frame height is the viewport height minus the frame's top, in pixels.
 */

/**
 * True when the web UI exists but this integration has no working password.
 *
 * ESPHome `web_server` `auth:` answers `GET /` with 401. That is a page,
 * not a missing `web_server`. The tab asks for the username and password
 * instead of embedding a challenge the browser would send to Home Assistant.
 *
 * HomeKit firmware (`passwordRequired`) is different: its page loads without
 * a password and shows its own login, which sends `X-API-Key` through the
 * proxy. That page is embedded as is.
 *
 * @param {{ firmware?: string, web?: boolean, password_required?: boolean, credentials_set?: boolean, auth_failed?: boolean } | null | undefined} device
 * @returns {boolean}
 */
export function needsWebLogin(device) {
  if (
    !device ||
    device.web === false ||
    !device.password_required ||
    device.firmware === "homekit"
  ) {
    return false;
  }
  return !device.credentials_set || device.auth_failed === true;
}

/**
 * @param {{ web?: boolean, password_required?: boolean, credentials_set?: boolean, auth_failed?: boolean } | null | undefined} device
 * @param {string | null | undefined} proxyUrl signed proxy URL
 * @param {"pending" | "loaded" | "failed"} frameState
 * @returns {"iframe" | "error" | "no-web" | "credentials" | "empty"}
 */
export function frameMode(device, proxyUrl, frameState) {
  if (!device) {
    return "empty";
  }
  if (device.web === false) {
    return "no-web";
  }
  if (needsWebLogin(device)) {
    return "credentials";
  }
  if (!proxyUrl || frameState === "failed") {
    return "error";
  }
  return "iframe";
}

/**
 * Pixel height for the embedded page.
 *
 * @param {number} viewportHeight window.innerHeight
 * @param {number} frameTop getBoundingClientRect().top of the frame
 * @param {number} [minimum]
 * @returns {number}
 */
export function frameHeight(viewportHeight, frameTop, minimum = 240) {
  const available = Math.floor(Number(viewportHeight) - Number(frameTop));
  if (!Number.isFinite(available)) {
    return minimum;
  }
  return Math.max(minimum, available);
}

/** How long to wait for the proxied page before showing the retry card. */
export const FRAME_LOAD_TIMEOUT_MS = 8000;

/** postMessage source the proxy hook and error page both use. */
export const PROXY_SOURCE = "ratgdo-mgmt-proxy";


/**
 * Whether a Lit update needs drawing. Home Assistant gives the panel a new
 * `hass` on every state change in the house; this page shows none of them,
 * so once it has been drawn, a change of `hass` alone is skipped.
 */
export function needsDraw(changed, hasUpdated) {
  if (!hasUpdated) return true;
  return !(changed.size === 1 && changed.has("hass"));
}

/**
 * Label of the header's Refresh button.
 *
 * @param {boolean} busy a refresh is running
 * @returns {string}
 */
export function refreshLabel(busy) {
  return busy ? "Refreshing…" : "Refresh";
}

/**
 * What the panel says when Refresh fails. Home Assistant's error message is
 * kept when there is one (for example "Unauthorized" for a non-admin).
 *
 * @param {unknown} err the rejection from callService
 * @returns {string}
 */
export function refreshErrorText(err) {
  const message =
    err && typeof err === "object" && typeof err.message === "string"
      ? err.message.trim()
      : "";
  return message
    ? `Couldn't refresh: ${message}`
    : "Couldn't refresh. Check that Home Assistant is running and try again.";
}
