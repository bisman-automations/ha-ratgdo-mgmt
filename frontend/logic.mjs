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
 * @param {{ web?: boolean } | null | undefined} device
 * @param {string | null | undefined} proxyUrl signed proxy URL
 * @param {"pending" | "loaded" | "failed"} frameState
 * @returns {"iframe" | "error" | "no-web" | "empty"}
 */
export function frameMode(device, proxyUrl, frameState) {
  if (!device) {
    return "empty";
  }
  if (device.web === false) {
    return "no-web";
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
