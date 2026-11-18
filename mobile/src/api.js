"use strict";

/* LanternApi: a small client for the Lantern JSON API.
 *
 * It covers every endpoint the Python server exposes (see
 * lantern/webapp.py): GET /api/status, /api/scans, /api/scans/latest,
 * /api/scans/{id}, /api/diff, /api/report, POST /api/scan, /api/demo,
 * /api/trust.
 *
 * baseUrl is the Lantern server origin, for example the address you
 * enter on the Settings screen. An empty baseUrl means same origin,
 * which is how the dashboard works in a desktop browser against a
 * local server. No server address is hard-coded here.
 *
 * Transport note: when this code runs inside the Capacitor app,
 * CapacitorHttp is used if it is available. CapacitorHttp sends the
 * request through the native layer, which bypasses the browser CORS
 * check. That matters because the Lantern server is same-origin only
 * and sends no CORS headers. On the plain web (desktop browser test),
 * the code falls back to fetch, which works when the page and the API
 * share an origin. If a future build finds fetch blocked by CORS on
 * device, the fix is either to keep CapacitorHttp enabled (the
 * default in capacitor.config.ts) or to add a narrow CORS allowance
 * to the server for the app origins (capacitor://localhost and
 * https://localhost). See docs/ADR-001-mobile-architecture.md.
 */

const DEFAULT_TIMEOUT_MS = 15000;

function capacitorHttp() {
  if (typeof window === "undefined") return null;
  const plugins = window.Capacitor && window.Capacitor.Plugins;
  const http = plugins && plugins.CapacitorHttp;
  if (http && typeof http.request === "function") return http;
  return null;
}

function joinUrl(baseUrl, path) {
  if (!baseUrl) return path;
  return baseUrl.replace(/\/+$/, "") + path;
}

class LanternApi {
  constructor(baseUrl, options) {
    this.baseUrl = (baseUrl || "").replace(/\/+$/, "");
    this.timeoutMs = (options && options.timeoutMs) || DEFAULT_TIMEOUT_MS;
  }

  setBaseUrl(baseUrl) {
    this.baseUrl = (baseUrl || "").replace(/\/+$/, "");
  }

  async request(path, options) {
    const opts = options || {};
    const method = (opts.method || "GET").toUpperCase();
    const url = joinUrl(this.baseUrl, path);
    const responseType = opts.responseType || "json";
    const timeoutMs = opts.timeoutMs || this.timeoutMs;
    const http = capacitorHttp();

    if (http) {
      const res = await http.request({
        url,
        method,
        headers: { "Content-Type": "application/json" },
        data: opts.body === undefined ? undefined : opts.body,
        responseType: responseType === "text" ? "text" : "json",
        connectTimeout: timeoutMs,
        readTimeout: timeoutMs,
      });
      const status = res.status || 0;
      const data = res.data;
      if (status < 200 || status >= 300) {
        const message = (data && data.error) || `Request failed (${status})`;
        throw new Error(message);
      }
      return data;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: controller.signal,
      });
    } catch (err) {
      if (err && err.name === "AbortError") {
        throw new Error(
          `Timed out after ${Math.round(timeoutMs / 1000)}s talking to ${this.baseUrl || "the Lantern server"}. ` +
            "Check the server address, and that the server is running."
        );
      }
      throw new Error(
        `Could not reach the Lantern server at ${this.baseUrl || "this origin"}. ` +
          "Check the server address, that the server is running, and that this device is on the same network or Tailscale."
      );
    } finally {
      clearTimeout(timer);
    }
    const data = responseType === "text" ? await res.text() : await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error((data && data.error) || `Request failed (${res.status})`);
    }
    return data;
  }

  getStatus() {
    return this.request("/api/status");
  }

  listScans() {
    return this.request("/api/scans");
  }

  getLatestScan() {
    return this.request("/api/scans/latest");
  }

  getScan(id) {
    if (!Number.isInteger(Number(id))) {
      return Promise.reject(new Error("Scan id must be a number."));
    }
    return this.request(`/api/scans/${id}`);
  }

  getDiff() {
    return this.request("/api/diff");
  }

  getReport(options) {
    const opts = options || {};
    const params = new URLSearchParams();
    if (opts.scanId) params.set("scan_id", String(opts.scanId));
    params.set("format", opts.format === "html" ? "html" : "json");
    const query = params.toString();
    return this.request(`/api/report?${query}`, {
      responseType: opts.format === "html" ? "text" : "json",
    });
  }

  runScan(subnet) {
    const body = {};
    if (subnet) body.subnet = subnet;
    return this.request("/api/scan", { method: "POST", body });
  }

  runDemo() {
    return this.request("/api/demo", { method: "POST", body: {} });
  }

  setTrust(mac, label, trusted) {
    return this.request("/api/trust", {
      method: "POST",
      body: { mac, label: label || "", trusted: trusted !== false },
    });
  }
}

if (typeof window !== "undefined") {
  window.LanternApi = LanternApi;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { LanternApi };
}
