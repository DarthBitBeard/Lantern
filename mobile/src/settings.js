"use strict";

/* Lantern mobile settings: the Lantern server address.
 *
 * The phone is a remote client in Phase 1. It does not scan anything
 * itself. It talks to a Lantern server running on a machine at home,
 * over the home LAN or over Tailscale. This module stores that server
 * address, validates it, and tests the connection.
 *
 * Storage is localStorage for now, because the bundled dashboard must
 * also work in a desktop browser for testing. TODO: move storage to
 * Capacitor Preferences (@capacitor/preferences, already a
 * dependency) once the native shell is wired up, so the address
 * survives app reinstalls the same way on iOS and Android and is not
 * tied to the WebView cache.
 *
 * Validation rules, all deliberate:
 * - http only. The Lantern server is plain HTTP. There is no TLS
 *   terminator in front of it, so https would never connect.
 * - A port is required. The Lantern default is 8068, and requiring
 *   the port avoids guessing wrong when a server runs elsewhere.
 * - The host must be localhost (testing only), a private RFC1918
 *   address (10/8, 172.16/12, 192.168/16), a Tailscale address
 *   (100.64/10, the CGNAT range Tailscale uses), a Tailscale
 *   MagicDNS hostname (a single label, or anything ending in
 *   .ts.net), or a .local mDNS hostname. Public IPs and public
 *   hostnames are refused. The dashboard has no login, so it must
 *   never point at a server exposed to the internet.
 * - No credentials, no path, no query string. Just scheme, host,
 *   and port.
 */

const STORAGE_KEY = "lantern.serverUrl";

function isIPv4(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function ipv4Octets(host) {
  return host.split(".").map((part) => Number(part));
}

function isPrivateOrTailscaleIPv4(host) {
  if (!isIPv4(host)) return false;
  const octets = ipv4Octets(host);
  if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = octets;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10, Tailscale
  return false;
}

function isLocalhost(host) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

function isAllowedHostname(host) {
  const lower = host.toLowerCase();
  if (lower.endsWith(".ts.net")) return true; // Tailscale tailnet DNS
  if (lower.endsWith(".local")) return true; // mDNS on the home LAN
  if (!lower.includes(".")) return true; // single label, Tailscale MagicDNS
  return false;
}

function validateServerUrl(raw) {
  const value = String(raw || "").trim();
  if (!value) {
    return { ok: false, error: "Enter a server address." };
  }
  let url;
  try {
    url = new URL(value);
  } catch (err) {
    return { ok: false, error: "That is not a valid URL. Use http://host:port." };
  }
  if (url.protocol !== "http:") {
    return { ok: false, error: "Use http, not https. The Lantern server is plain HTTP." };
  }
  if (url.username || url.password) {
    return { ok: false, error: "Do not put a username or password in the server address." };
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    return { ok: false, error: "Enter just the server address, no path after the port." };
  }
  if (url.search || url.hash) {
    return { ok: false, error: "Enter just the server address, no extra text after the port." };
  }
  if (!url.port) {
    return { ok: false, error: "Include a port, for example :8068." };
  }
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "Port must be a number from 1 to 65535." };
  }
  const host = url.hostname;
  if (!host) {
    return { ok: false, error: "Enter a server address." };
  }
  if (isLocalhost(host)) {
    return { ok: true, normalized: `http://${host}:${port}` };
  }
  if (isIPv4(host)) {
    if (!isPrivateOrTailscaleIPv4(host)) {
      return { ok: false, error: "That IP is public. Lantern only talks to private or Tailscale addresses." };
    }
    return { ok: true, normalized: `http://${host}:${port}` };
  }
  if (isAllowedHostname(host)) {
    return { ok: true, normalized: `http://${host}:${port}` };
  }
  return { ok: false, error: "That host looks public. Use a private IP, a Tailscale hostname, or localhost." };
}

function loadServerUrl() {
  try {
    return window.localStorage.getItem(STORAGE_KEY) || "";
  } catch (err) {
    return "";
  }
}

function saveServerUrl(raw) {
  const checked = validateServerUrl(raw);
  if (!checked.ok) return checked;
  try {
    window.localStorage.setItem(STORAGE_KEY, checked.normalized);
  } catch (err) {
    return { ok: false, error: "Could not save the server address in this browser." };
  }
  return { ok: true, normalized: checked.normalized };
}

function clearServerUrl() {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    // Storage is best effort here. A failed clear just leaves the value.
  }
}

async function testConnection(api) {
  const client = api || new window.LanternApi(loadServerUrl());
  try {
    const status = await client.getStatus();
    return {
      ok: true,
      version: status.version || "unknown",
      scanCount: typeof status.scan_count === "number" ? status.scan_count : 0,
      guessedSubnet: status.guessed_subnet || "",
      latestScanId: status.latest_scan_id ?? null,
    };
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : String(err) };
  }
}

const LanternSettings = {
  STORAGE_KEY,
  validateServerUrl,
  loadServerUrl,
  saveServerUrl,
  clearServerUrl,
  testConnection,
};

if (typeof window !== "undefined") {
  window.LanternSettings = LanternSettings;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = LanternSettings;
}
