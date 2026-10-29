"use strict";

const $ = (id) => document.getElementById(id);
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const TOKEN_STORAGE = "lantern-token";

function pageToken() {
  const meta = document.querySelector('meta[name="lantern-token"]');
  const value = meta ? meta.getAttribute("content") || "" : "";
  if (!value || value === "__LANTERN_TOKEN__") return "";
  return value;
}

function storedToken() {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE) || "";
  } catch (err) {
    return "";
  }
}

function lanternToken() {
  // Default mode trusts the token embedded in the page. A stored value must
  // not override it, or a crafted #token= link would break later requests.
  if (needsStoredToken()) return storedToken() || pageToken();
  return pageToken() || storedToken();
}

function authMode() {
  const meta = document.querySelector('meta[name="lantern-auth"]');
  return meta ? meta.getAttribute("content") || "" : "";
}

function lanMode() {
  return authMode() === "token";
}

function needsStoredToken() {
  const mode = authMode();
  return mode === "token" || mode === "strict";
}

function takeFragmentToken() {
  // The fragment is never sent to the server. Move it into this tab and
  // strip it from the address bar so a copied URL does not keep the token.
  let hash = "";
  try {
    hash = window.location.hash || "";
  } catch (err) {
    return "";
  }
  const mark = "#token=";
  if (hash.indexOf(mark) !== 0) return "";
  let value = hash.slice(mark.length);
  try {
    value = decodeURIComponent(value);
  } catch (err) {
    value = hash.slice(mark.length);
  }
  value = value.trim();
  if (value) {
    try {
      sessionStorage.setItem(TOKEN_STORAGE, value);
    } catch (err) { /* private mode */ }
  }
  try {
    const path = (window.location.pathname || "/") + (window.location.search || "");
    history.replaceState(null, "", path);
  } catch (err) { /* cannot rewrite this URL */ }
  return value;
}

function showTokenPrompt() {
  const box = $("token-entry");
  if (!box) return;
  box.hidden = false;
  $("status").textContent = "Token required";
}

// View state. `viewingId` is null when showing the latest scan.
let currentScan = null;
let currentDiff = null;
let viewingId = null;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? String(iso) : date.toLocaleString();
}

function worstSeverity(device) {
  let worst = null;
  for (const f of device.findings || []) {
    if (!(f.severity in SEVERITY_ORDER)) continue;
    if (!worst || SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[worst]) worst = f.severity;
  }
  return worst;
}

function setMessage(text, isError) {
  const el = $("message");
  el.textContent = text || "";
  el.className = isError ? "message error" : "message";
}

function setBusy(busy) {
  document.body.setAttribute("aria-busy", busy ? "true" : "false");
  for (const id of ["scan-btn", "demo-btn", "refresh-btn"]) $(id).disabled = busy;
  $("history").disabled = busy;
}

async function api(path, options) {
  const opts = { ...(options || {}) };
  const headers = { ...(opts.headers || {}) };
  const token = lanternToken();
  if (token) headers["X-Lantern-Token"] = token;
  opts.headers = headers;
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (res.status === 403 && needsStoredToken()) {
    try { sessionStorage.removeItem(TOKEN_STORAGE); } catch (err) { /* private mode */ }
    showTokenPrompt();
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function postJson(path, body) {
  return api(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Lantern-Token": lanternToken(),
    },
    body: JSON.stringify(body ?? {}),
  });
}

function describeChange(change) {
  const parts = [];
  if (change.old_ip && change.old_ip !== change.device.ip) parts.push(`moved from ${esc(change.old_ip)}`);
  if (change.opened.length) parts.push(`opened ${change.opened.join(", ")}`);
  if (change.closed.length) parts.push(`closed ${change.closed.join(", ")}`);
  return `${esc(change.device.ip)}: ${parts.join("; ") || "no change"}`;
}

function renderSummary(scan, diff) {
  const el = $("summary");
  if (!scan) {
    el.innerHTML = "";
    $("status").textContent = "No scans yet";
    return;
  }
  const critical = scan.devices.filter((d) => worstSeverity(d) === "critical").length;
  const high = scan.devices.filter((d) => worstSeverity(d) === "high").length;
  const unknown = scan.devices.filter((d) => !d.trusted).length;
  const added = diff ? diff.added.length : 0;
  el.innerHTML = `
    <div class="stat"><b>${scan.devices.length}</b><span>devices</span></div>
    <div class="stat ${added ? "warn" : ""}"><b>${added}</b><span>new since previous scan</span></div>
    <div class="stat ${unknown ? "warn" : ""}"><b>${unknown}</b><span>unknown / untrusted</span></div>
    <div class="stat ${critical ? "bad" : ""}"><b>${critical}</b><span>critical devices</span></div>
    <div class="stat ${high ? "warn" : ""}"><b>${high}</b><span>high-risk devices</span></div>`;
  if (scan.scope_name) el.innerHTML += `<p>Scope: ${esc(scan.scope_name)}</p>`;
  const which = viewingId === null ? "Latest" : `Scan #${scan.id}`;
  const scopeText = scan.scope_name ? ` | ${scan.scope_name}` : "";
  $("status").textContent = `${which} | ${scan.subnet}${scopeText} | ${formatTime(scan.started_at)}${scan.demo ? " | demo" : ""}`;
}

function renderDiff(scan, diff) {
  const el = $("diff");
  if (!scan || !diff) {
    el.className = "diff calm";
    const why = scan ? "This is the first saved scan, so there is nothing to compare it with yet."
      : "Run two scans to see what changed. The demo does this for you.";
    el.innerHTML = `<h2>What changed</h2><p>${why}</p>`;
    return;
  }
  const calm = diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0;
  el.className = calm ? "diff calm" : "diff";
  const added = diff.added.map((d) => esc(d.ip)).join(", ") || "none";
  const removed = diff.removed.map((d) => esc(d.ip)).join(", ") || "none";
  const changedText = diff.changed.map(describeChange).join("; ") || "none";
  el.innerHTML = `<h2>What changed since the previous scan</h2>
    <p><strong>New devices:</strong> ${added}</p>
    <p><strong>Devices gone:</strong> ${removed}</p>
    <p><strong>Port changes:</strong> ${changedText}</p>
    ${calm ? "<p>Nothing changed. Good news.</p>" : ""}`;
}

function deviceMatches(device) {
  const q = $("search").value.trim().toLowerCase();
  const filter = $("filter").value;
  if (filter === "unknown" && device.trusted) return false;
  if (filter === "trusted" && !device.trusted) return false;
  if (filter === "risky" && !["critical", "high"].includes(worstSeverity(device))) return false;
  if (!q) return true;
  const hay = [device.ip, device.mac, device.hostname, device.label]
    .concat((device.open_ports || []).map((p) => String(p.port)))
    .filter(Boolean).join(" ").toLowerCase();
  return hay.includes(q);
}

function renderDevice(device) {
  const name = esc(device.label || device.hostname || device.ip);
  const worst = worstSeverity(device);
  const ports = device.open_ports.map((p) =>
    `<span class="port" ${p.banner ? `title="${esc(p.banner)}"` : ""}>${esc(p.port)}</span>`
  ).join("") || "<span class='port'>none</span>";
  const findings = (device.findings || []).map((f) => `
    <li><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
    <strong> ${esc(f.port)} ${esc(f.service)}:</strong> ${esc(f.title)}
    <small>${esc(f.fix)}</small></li>`).join("") || "<li>No risky open ports found.</li>";
  const trustBadge = device.trusted
    ? `<span class="badge trusted">trusted</span>`
    : `<span class="badge unknown">unknown</span>`;
  const mac = device.mac || "";
  const disabled = mac ? "" : "disabled";
  const fingerprints = Array.isArray(device.fingerprints) ? device.fingerprints : [];
  let fingerprintText = "";
  if (fingerprints.length) {
    fingerprintText = fingerprints.map((row) => {
      const bits = [row.port, row.service, row.product, row.version].filter((part) => part !== null && part !== undefined && part !== "");
      let line = bits.join(" ");
      if (row.parse_status === "rejected") line = `${line} (banner rejected)`.trim();
      else if (row.parse_status === "unknown" && !row.version) {
        line = `${line} (${row.product ? "version unknown" : "not identified"})`.trim();
      }
      return line;
    }).join("; ");
  } else if ((device.open_ports || []).length) {
    fingerprintText = "not fingerprinted";
  }
  const extra = [
    fingerprintText ? `<p>Fingerprint: ${esc(fingerprintText)} (self-reported banner, not verified)</p>` : "",
    device.label && device.hostname ? `<p>Hostname: ${esc(device.hostname)}</p>` : "",
    device.owner ? `<p>Owner: ${esc(device.owner)}</p>` : "",
    Array.isArray(device.tags) && device.tags.length
      ? `<p>Tags: ${device.tags.map((tag) => esc(tag)).join(", ")}</p>`
      : "",
    device.notes ? `<p>Notes: ${esc(device.notes)}</p>` : "",
  ].join("");
  return `<article class="device ${device.trusted ? "" : "unknown"}">
    <h2>${name} ${trustBadge}</h2>
    <p class="meta">${esc(device.ip)}${mac ? ` &middot; ${esc(mac)}` : ""}${device.hostname ? ` &middot; ${esc(device.hostname)}` : ""}</p>
    ${extra}
    ${worst ? `<p>Worst risk: <span class="badge ${esc(worst)}">${esc(worst)}</span></p>` : ""}
    <div class="ports">${ports}</div>
    <ul class="findings">${findings}</ul>
    <div class="trust-row">
      <input name="label-${esc(mac || device.ip)}" data-label-for="${esc(mac)}" value="${esc(device.label || "")}" maxlength="80" placeholder="Label, e.g. Living room TV" ${disabled} aria-label="Label for ${esc(device.ip)}">
      <button type="button" class="secondary" data-trust="${esc(mac)}" ${disabled}>Trust</button>
      <button type="button" class="secondary" data-untrust="${esc(mac)}" ${disabled}>Mark unknown</button>
    </div>
    ${mac ? "" : "<p class='hint'>No MAC address, so this device cannot be trusted yet. It is tracked by IP only.</p>"}
  </article>`;
}

function renderDevices() {
  const el = $("devices");
  if (!currentScan) {
    el.innerHTML = `<div class="empty"><p>No scans yet.</p><p>Run the demo, or run a scan of your own network.</p></div>`;
    return;
  }
  const devices = currentScan.devices.filter(deviceMatches);
  if (!devices.length) {
    el.innerHTML = `<div class="empty"><p>No devices match this filter.</p></div>`;
    return;
  }
  el.innerHTML = devices.map(renderDevice).join("");
  el.querySelectorAll("[data-trust]").forEach((btn) => {
    btn.addEventListener("click", () => saveTrust(btn.dataset.trust, true, btn));
  });
  el.querySelectorAll("[data-untrust]").forEach((btn) => {
    btn.addEventListener("click", () => saveTrust(btn.dataset.untrust, false, btn));
  });
  el.querySelectorAll("[data-label-for]").forEach((input) => {
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      const btn = el.querySelector(`[data-trust="${CSS.escape(input.dataset.labelFor)}"]`);
      if (btn) btn.click();
    });
  });
}

function showScan(scan, diff) {
  currentScan = scan;
  currentDiff = diff;
  renderSummary(currentScan, currentDiff);
  renderDiff(currentScan, currentDiff);
  renderDevices();
  $("report-link").href = viewingId === null
    ? "/api/report?format=html"
    : `/api/report?format=html&scan_id=${encodeURIComponent(viewingId)}`;
}

async function saveTrust(mac, trusted, btn) {
  const input = document.querySelector(`[data-label-for="${CSS.escape(mac)}"]`);
  const label = input ? input.value.trim() : "";
  btn.disabled = true;
  try {
    await postJson("/api/trust", { mac, label, trusted });
    setMessage(trusted ? `Trusted ${mac}${label ? ` as ${label}` : ""}.` : `Marked ${mac} unknown.`);
    await reloadCurrentView();
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

function historyOption(scan) {
  const scope = scan.scope_name ? ` ${esc(scan.scope_name)}` : "";
  return `<option value="${esc(scan.id)}">#${esc(scan.id)} ${esc(formatTime(scan.started_at))}${scope} (${esc(scan.device_count)} devices)${scan.demo ? " demo" : ""}</option>`;
}

async function loadHistory() {
  const data = await api("/api/scans");
  const select = $("history");
  select.innerHTML = `<option value="">Latest scan</option>` + data.scans.map(historyOption).join("");
  select.value = viewingId === null ? "" : String(viewingId);
  if (select.value !== (viewingId === null ? "" : String(viewingId))) {
    // The selected scan no longer exists; fall back to latest.
    viewingId = null;
    select.value = "";
  }
}

async function loadLatest() {
  viewingId = null;
  const data = await api("/api/scans/latest");
  showScan(data.scan, data.diff);
  return data;
}

async function loadScanById(id) {
  if (!id) return loadLatest();
  const data = await api(`/api/scans/${encodeURIComponent(id)}`);
  viewingId = data.scan.id;
  showScan(data.scan, data.diff);
  return data;
}

async function reloadCurrentView() {
  if (viewingId === null) await loadLatest();
  else await loadScanById(viewingId);
  await loadHistory();
}

async function loadStatus() {
  const data = await api("/api/status");
  if (data.guessed_subnet && !$("subnet").value) $("subnet").value = data.guessed_subnet;
  if (data.version) $("version").textContent = `Lantern v${data.version}`;
  if (data.scan_running) setMessage("A scan started elsewhere is still running.");
  return data;
}

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  setMessage("Scanning. This can take a minute on a /24.");
  try {
    const data = await postJson("/api/scan", { subnet: $("subnet").value.trim() || undefined });
    viewingId = null;
    showScan(data.scan, data.diff);
    await loadHistory();
    setMessage(`Scan done: ${data.scan.devices.length} devices.`);
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    setBusy(false);
  }
});

$("demo-btn").addEventListener("click", async () => {
  setBusy(true);
  setMessage("Running demo scans.");
  try {
    await postJson("/api/demo", {});
    await loadLatest();
    await loadHistory();
    setMessage("Demo done. Look for the new device with Telnet open.");
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    setBusy(false);
  }
});

$("refresh-btn").addEventListener("click", async () => {
  try {
    await reloadCurrentView();
    setMessage("");
  } catch (err) {
    setMessage(err.message, true);
  }
});

$("report-link").addEventListener("click", async (event) => {
  event.preventDefault();
  try {
    const headers = {};
    const token = lanternToken();
    if (token) headers["X-Lantern-Token"] = token;
    const res = await fetch($("report-link").getAttribute("href"), { headers });
    if (res.status === 403 && needsStoredToken()) {
      try { sessionStorage.removeItem(TOKEN_STORAGE); } catch (err) { /* private mode */ }
      showTokenPrompt();
    }
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    const html = await res.text();
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener");
  } catch (err) {
    setMessage(err.message, true);
  }
});

$("search").addEventListener("input", renderDevices);
$("filter").addEventListener("change", renderDevices);
$("history").addEventListener("change", async (event) => {
  try {
    await loadScanById(event.target.value);
    setMessage("");
  } catch (err) {
    setMessage(err.message, true);
  }
});

async function startDashboard() {
  try {
    await loadStatus();
    await loadLatest();
    await loadHistory();
  } catch (err) {
    $("status").textContent = "Could not reach the Lantern server.";
    setMessage(err.message, true);
  }
}

const tokenForm = $("token-form");
if (tokenForm) {
  tokenForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = $("api-token").value.trim();
    if (value.length < 22) {
      setMessage("That token is too short.", true);
      return;
    }
    try {
      sessionStorage.setItem(TOKEN_STORAGE, value);
    } catch (err) {
      setMessage("This browser blocked session storage.", true);
      return;
    }
    $("api-token").value = "";
    $("token-entry").hidden = true;
    setMessage("");
    startDashboard();
  });
}

if (needsStoredToken()) {
  takeFragmentToken();
  const note = $("exposure-note");
  if (note && lanMode()) {
    note.textContent = "LAN mode. Every API call needs the startup token. Data stays in one SQLite file on this machine. Never expose this port to the internet.";
  } else if (note) {
    note.textContent = "Strict auth. Every API call needs the startup token. It is not in this page.";
  }
  if (!storedToken()) showTokenPrompt();
  else startDashboard();
} else {
  startDashboard();
}
