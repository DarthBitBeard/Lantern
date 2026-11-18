"use strict";

/* Mobile bootstrap for the Lantern dashboard.
 *
 * This file is loaded in www/index.html before app.js. It does two
 * things, in this order:
 *
 * 1. It installs a fetch shim, synchronously at load time, so the
 *    existing dashboard code (app.js) needs no changes. app.js calls
 *    fetch("/api/...") with relative paths. When a Lantern server is
 *    configured, the shim rewrites those calls to absolute URLs on
 *    that server. When no server is configured, fetch is untouched
 *    and the dashboard works same-origin in a desktop browser, which
 *    is how you test it before the native shell exists.
 *
 * 2. On DOMContentLoaded it builds the Settings screen: a server
 *    address field, a Save button, and a Test Connection button,
 *    wired to LanternSettings and LanternApi. It also rewrites the
 *    "Open HTML report" link to the configured server, because that
 *    link is a plain navigation, not a fetch call, so the shim cannot
 *    fix it. A MutationObserver keeps the rewrite applied when
 *    app.js changes the link for a historical scan.
 *
 * Nothing here scans the network. The phone stays a remote client.
 * Scanning still runs on the Lantern server at home.
 */

(function () {
  if (typeof window === "undefined") return;

  const settings = window.LanternSettings;
  const ApiClass = window.LanternApi;
  if (!settings || !ApiClass) return;

  let serverUrl = settings.loadServerUrl();
  const api = new ApiClass(serverUrl);

  // -- fetch shim (installed immediately, before app.js runs) --------
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    let url = typeof input === "string" ? input : input && input.url;
    if (serverUrl && typeof url === "string" && url.startsWith("/")) {
      url = serverUrl.replace(/\/+$/, "") + url;
      if (typeof input === "string") {
        return nativeFetch(url, init);
      }
      return nativeFetch(new Request(url, input), init);
    }
    return nativeFetch(input, init);
  };

  // -- report link rewrite -------------------------------------------
  function rewriteReportLink() {
    const link = document.getElementById("report-link");
    if (!link || !serverUrl) return;
    const href = link.getAttribute("href") || "";
    if (href.startsWith("/")) {
      link.setAttribute("href", serverUrl.replace(/\/+$/, "") + href);
    }
  }

  function watchReportLink() {
    const link = document.getElementById("report-link");
    if (!link || typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(rewriteReportLink);
    observer.observe(link, { attributes: true, attributeFilter: ["href"] });
  }

  // -- settings screen ------------------------------------------------
  function buildSettings() {
    const main = document.querySelector("main");
    if (!main) return;
    const section = document.createElement("section");
    section.className = "controls";
    section.id = "mobile-settings";
    section.innerHTML =
      '<h2 style="margin: 0 0 0.5rem; font-size: 1.1rem;">Lantern server</h2>' +
      '<form id="server-form">' +
      '<label for="server-url">Server address</label>' +
      '<input id="server-url" name="server-url" type="text" placeholder="http://your-server:8068" autocomplete="off" inputmode="url">' +
      '<button type="submit" id="server-save-btn">Save</button>' +
      '<button type="button" id="server-test-btn" class="secondary">Test connection</button>' +
      "</form>" +
      '<p id="server-message" class="message" role="status"></p>' +
      '<p class="hint">Your phone is a remote client. Scanning runs on the Lantern server at home, over your home network or Tailscale. ' +
      "The dashboard has no login, so only point it at a private or Tailscale address. Never expose the server to the internet.</p>";
    main.insertBefore(section, main.firstChild);

    const input = document.getElementById("server-url");
    const message = document.getElementById("server-message");
    input.value = serverUrl;

    function setMessage(text, isError) {
      message.textContent = text || "";
      message.className = isError ? "message error" : "message";
    }

    if (!serverUrl) {
      setMessage("No Lantern server set yet. Enter your home server address above, then save.");
    }

    document.getElementById("server-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const checked = settings.saveServerUrl(input.value);
      if (!checked.ok) {
        setMessage(checked.error, true);
        return;
      }
      serverUrl = checked.normalized;
      api.setBaseUrl(serverUrl);
      setMessage(`Saved. Connecting to ${serverUrl}. Reloading.`);
      window.location.reload();
    });

    document.getElementById("server-test-btn").addEventListener("click", async () => {
      const checked = settings.validateServerUrl(input.value);
      if (!checked.ok) {
        setMessage(checked.error, true);
        return;
      }
      const probe = new ApiClass(checked.normalized);
      setMessage("Testing connection.");
      const result = await settings.testConnection(probe);
      if (!result.ok) {
        setMessage(`Could not reach the server: ${result.error}`, true);
        return;
      }
      setMessage(
        `Connected. Lantern ${result.version}, ${result.scanCount} scan(s) saved` +
          (result.guessedSubnet ? `, server subnet ${result.guessedSubnet}.` : ".")
      );
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      buildSettings();
      rewriteReportLink();
      watchReportLink();
    });
  } else {
    buildSettings();
    rewriteReportLink();
    watchReportLink();
  }

  window.LanternMobile = { api, getServerUrl: () => serverUrl };
})();
