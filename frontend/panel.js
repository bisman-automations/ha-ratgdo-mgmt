import { LitElement, css, html } from "lit";

import {
  FRAME_LOAD_TIMEOUT_MS,
  PROXY_SOURCE,
  frameHeight,
  frameMode,
} from "./logic.mjs";

/**
 * Admin sidebar panel: one tab per ratgdo.
 *
 * The iframe loads a signed Home Assistant proxy URL, not the controller.
 * The signed URL lasts a few minutes. This element refreshes it, and the
 * cookie it sets, without navigating the iframe away from the page the
 * user is on. The iframe's height is set in pixels from the viewport,
 * because the custom panel host has no definite height of its own.
 */
class RatgdoMgmtPanel extends LitElement {
  static properties = {
    hass: { attribute: false },
    narrow: { type: Boolean },
    panel: { attribute: false },
    _devices: { state: true },
    _selected: { state: true },
    _frame: { state: true },
    _attempt: { state: true },
    _iframeUrl: { state: true },
    _openUrl: { state: true },
    _framePx: { state: true },
  };

  constructor() {
    super();
    this._devices = [];
    this._selected = null;
    this._frame = "pending";
    this._attempt = 0;
    this._iframeUrl = null;
    this._openUrl = null;
    this._framePx = 240;
    this._unsub = null;
    this._pending = false;
    this._timer = 0;
    this._renewTimer = 0;
    this._signGen = 0;
    this._onMessage = (event) => this._handleMessage(event);
    this._onResize = () => this._measure();
  }

  connectedCallback() {
    super.connectedCallback();
    window.addEventListener("message", this._onMessage);
    window.addEventListener("resize", this._onResize);
    this._subscribe();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    window.removeEventListener("message", this._onMessage);
    window.removeEventListener("resize", this._onResize);
    this._clearTimers();
    if (this._unsub) {
      this._unsub();
      this._unsub = null;
    }
  }

  updated(changed) {
    if (changed.has("hass")) {
      this._subscribe();
    }
    if (changed.has("_selected") || changed.has("_attempt")) {
      this._sign(true);
    }
    this._measure();
  }

  async _subscribe() {
    if (!this.hass || this._unsub || this._pending) {
      return;
    }
    this._pending = true;
    this._unsub = await this.hass.connection.subscribeMessage(
      (event) => {
        this._devices = event.devices || [];
        if (!this._devices.some((device) => device.id === this._selected)) {
          this._selected = this._devices[0] ? this._devices[0].id : null;
          this._frame = "pending";
        }
      },
      { type: "ratgdo_mgmt/subscribe" },
    );
  }

  get _device() {
    return this._devices.find((device) => device.id === this._selected) || null;
  }

  _select(id) {
    if (id === this._selected) {
      return;
    }
    this._selected = id;
    this._frame = "pending";
    this._iframeUrl = null;
    this._attempt += 1;
  }

  _measure() {
    const node = this.renderRoot.querySelector("[data-frame]");
    if (!node) {
      return;
    }
    const next = frameHeight(window.innerHeight, node.getBoundingClientRect().top);
    if (next !== this._framePx) {
      this._framePx = next;
    }
    node.style.height = `${next}px`;
  }

  async _sign(navigate) {
    const device = this._device;
    const generation = ++this._signGen;
    this._clearTimers();
    if (!device || !this.hass || device.web === false) {
      this._iframeUrl = null;
      this._openUrl = null;
      return;
    }
    try {
      const result = await this.hass.connection.sendMessagePromise({
        type: "ratgdo_mgmt/sign_proxy",
        device_id: device.id,
      });
      if (generation !== this._signGen) {
        return;
      }
      this._openUrl = result.url;
      if (navigate) {
        this._iframeUrl = result.url;
        this._frame = "pending";
        this._armLoadTimer();
      }
      this._armRenew(result.expires_in);
    } catch (_err) {
      if (generation !== this._signGen) {
        return;
      }
      this._iframeUrl = null;
      this._openUrl = null;
      this._frame = "failed";
    }
  }

  _armLoadTimer() {
    this._timer = window.setTimeout(() => {
      if (this._frame !== "loaded") {
        this._frame = "failed";
      }
    }, FRAME_LOAD_TIMEOUT_MS);
  }

  _armRenew(expiresIn) {
    const seconds = Number(expiresIn) || 300;
    const delay = Math.max(15, seconds - 60) * 1000;
    this._renewTimer = window.setTimeout(() => this._renew(), delay);
  }

  async _renew() {
    const device = this._device;
    if (!device || !this.hass || device.web === false) {
      return;
    }
    try {
      const result = await this.hass.connection.sendMessagePromise({
        type: "ratgdo_mgmt/sign_proxy",
        device_id: device.id,
      });
      this._openUrl = result.url;
      await fetch(result.url, {
        credentials: "same-origin",
        redirect: "manual",
        cache: "no-store",
      });
      this._armRenew(result.expires_in);
    } catch (_err) {
      this._armRenew(60);
    }
  }

  _clearTimers() {
    if (this._timer) {
      window.clearTimeout(this._timer);
      this._timer = 0;
    }
    if (this._renewTimer) {
      window.clearTimeout(this._renewTimer);
      this._renewTimer = 0;
    }
  }

  _handleMessage(event) {
    if (event.origin !== window.location.origin) {
      return;
    }
    const data = event.data;
    if (!data || data.source !== PROXY_SOURCE) {
      return;
    }
    if (data.ok) {
      if (this._timer) {
        window.clearTimeout(this._timer);
        this._timer = 0;
      }
      this._frame = "loaded";
      return;
    }
    this._frame = "failed";
  }

  _retry() {
    this._frame = "pending";
    this._iframeUrl = null;
    this._attempt += 1;
  }

  async _refresh() {
    await this.hass.callService("ratgdo_mgmt", "refresh");
  }

  render() {
    const device = this._device;
    return html`
      <div class="wrap">
        <header>
          <h1>ratgdo Mgmt</h1>
          <button class="quiet" @click=${this._refresh}>Refresh</button>
        </header>
        ${this._devices.length
          ? html`
              <div class="tabs" role="tablist">
                ${this._devices.map(
                  (item) => html`
                    <button
                      role="tab"
                      class=${item.id === this._selected ? "tab on" : "tab"}
                      aria-selected=${item.id === this._selected}
                      @click=${() => this._select(item.id)}
                    >
                      <span class="dot ${item.online ? "on" : ""}"></span>
                      ${item.name}
                    </button>
                  `,
                )}
              </div>
              ${device ? this._body(device) : ""}
            `
          : html`<p class="empty">No ratgdo controllers found yet.</p>`}
      </div>
    `;
  }

  _body(device) {
    const mode = frameMode(device, this._iframeUrl, this._frame);
    const seen = device.last_seen
      ? new Date(device.last_seen).toLocaleString()
      : "Not yet";
    const openUrl = this._openUrl || device.url;
    const height = `${this._framePx}px`;
    return html`
      <section class="info">
        <div><span>Name</span><strong>${device.name}</strong></div>
        <div><span>IP</span><strong>${device.host}</strong></div>
        <div>
          <span>Firmware</span><strong>${device.firmware || "Unknown"}</strong>
        </div>
        <div>
          <span>Version</span
          ><strong>${device.firmware_version || "Unknown"}</strong>
        </div>
        <div>
          <span>Status</span>
          <strong>${device.online ? "Online" : "Offline"}</strong>
        </div>
        <div><span>Last seen</span><strong>${seen}</strong></div>
        ${mode !== "no-web"
          ? html`<a href=${openUrl} target="_blank" rel="noopener noreferrer"
              >Open in new tab</a
            >`
          : ""}
      </section>
      ${mode === "no-web"
        ? html`
            <div class="card" data-frame style="height: ${height}">
              <h2>No web page on this controller</h2>
              <p>
                This ESPHome build did not answer on its web port.
                <code>web_server:</code> is in the stock ratgdo ESPHome
                packages and can be left out of a custom one. Door controls
                stay on the ESPHome integration. What ratgdo Mgmt can see
                without the page:
              </p>
              <ul>
                <li>Project: ${device.project_name || "Unknown"}</li>
                <li>Version: ${device.firmware_version || "Unknown"}</li>
                <li>Board: ${device.board || "Unknown"}</li>
                <li>MAC: ${device.mac || "Unknown"}</li>
                <li>Address: ${device.host}</li>
              </ul>
            </div>
          `
        : mode === "error"
          ? html`
              <div class="card" data-frame style="height: ${height}">
                <h2>Can't load the web page</h2>
                <p>
                  Home Assistant couldn't show this controller's web page.
                  Retry the connection through Home Assistant, or open the
                  controller directly.
                </p>
                <div class="actions">
                  <button class="button" @click=${this._retry}>Retry</button>
                  <a
                    class="button"
                    href=${openUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    >Open in new tab</a
                  >
                  <a
                    class="button quiet-link"
                    href=${device.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    >Open controller directly</a
                  >
                </div>
              </div>
            `
          : html`
              <iframe
                data-frame
                title=${`Web page for ${device.name}`}
                src=${this._iframeUrl}
                style="height: ${height}"
                @error=${() => {
                  this._frame = "failed";
                }}
              ></iframe>
            `}
    `;
  }

  static styles = css`
    :host {
      display: block;
      background: var(--primary-background-color, #111);
      color: var(--primary-text-color, #e8e8e8);
      box-sizing: border-box;
    }
    .wrap {
      display: flex;
      flex-direction: column;
      box-sizing: border-box;
      min-height: 100%;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 16px 0;
    }
    h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 500;
    }
    .quiet,
    .button {
      background: var(--primary-color, #03a9f4);
      color: var(--text-primary-color, #fff);
      border: 0;
      border-radius: 8px;
      padding: 8px 14px;
      text-decoration: none;
      cursor: pointer;
      font: inherit;
    }
    .quiet-link {
      background: transparent;
      color: var(--primary-color, #03a9f4);
      border: 1px solid var(--primary-color, #03a9f4);
    }
    .tabs {
      display: flex;
      gap: 8px;
      padding: 12px 16px;
      overflow-x: auto;
    }
    .tab {
      display: flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--divider-color, #333);
      background: var(--card-background-color, #1c1c1c);
      color: inherit;
      border-radius: 999px;
      padding: 6px 12px;
      cursor: pointer;
      font: inherit;
      white-space: nowrap;
    }
    .tab.on {
      border-color: var(--primary-color, #03a9f4);
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #888;
      flex: 0 0 auto;
    }
    .dot.on {
      background: var(--success-color, #4caf50);
    }
    .info {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      align-items: end;
      padding: 0 16px 12px;
    }
    .info span {
      display: block;
      font-size: 12px;
      opacity: 0.7;
    }
    .info a {
      color: var(--primary-color, #03a9f4);
    }
    iframe {
      width: 100%;
      border: 0;
      background: #fff;
      display: block;
    }
    .card,
    .empty {
      margin: 8px 16px;
      padding: 20px;
      border-radius: 12px;
      background: var(--card-background-color, #1c1c1c);
      box-sizing: border-box;
      overflow: auto;
    }
    .card h2 {
      margin: 0 0 8px;
      font-size: 18px;
    }
    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    @media (max-width: 600px) {
      header,
      .info {
        padding-left: 12px;
        padding-right: 12px;
      }
      .tabs {
        padding-left: 12px;
        padding-right: 12px;
      }
    }
  `;
}

customElements.define("ratgdo-mgmt-panel", RatgdoMgmtPanel);
