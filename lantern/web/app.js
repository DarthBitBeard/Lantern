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
  const identity = device.identity || {};
  const hay = [device.ip, device.mac, device.hostname, device.label, identity.name,
    identity.model, identity.manufacturer, KIND_LABELS[device.kind]]
    .concat(identity.names || [])
    .concat((device.open_ports || []).map((p) => String(p.port)))
    .filter(Boolean).join(" ").toLowerCase();
  return hay.includes(q);
}

// A set 0x02 bit in the first byte marks a locally administered address.
// Phones use these as "private Wi-Fi addresses" and change them, so the
// same phone can look like a new device.
function isRandomizedMac(mac) {
  const first = /^([0-9a-f]{2})[:-]/i.exec(mac || "");
  return Boolean(first) && (parseInt(first[1], 16) & 2) === 2;
}

const KIND_LABELS = {
  router: "Router", network: "Network gear", computer: "Computer", server: "Server",
  nas: "Storage (NAS)", printer: "Printer", camera: "Camera", media: "TV / media",
  smart_home: "Smart home", phone: "Phone / tablet", other: "Other device", unknown: "Unknown",
};

function displayName(device) {
  const identity = device.identity || {};
  return device.label || identity.name || device.hostname || device.ip;
}

function identityLine(device) {
  const identity = device.identity || {};
  const parts = [identity.manufacturer, identity.model]
    .filter((v, i, all) => v && all.indexOf(v) === i);
  if (identity.name && identity.name !== displayName(device)) parts.unshift(identity.name);
  return parts.join(" · ");
}

function switchPortLine(device) {
  const where = device.switch_port;
  if (!where) return "";
  const shared = where.shared
    ? ` (shared with ${esc(Math.max(1, (where.mac_count || 2) - 1))} other address(es): usually Wi-Fi or an unmanaged switch)`
    : "";
  return `<p>Switch: ${esc(where.switch_name || where.switch)}, ${esc(where.port)}${shared}</p>`;
}

function renderDevice(device) {
  const name = esc(displayName(device));
  const kind = KIND_LABELS[device.kind];
  const announced = identityLine(device);
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
  const extra = [
    device.label && device.hostname ? `<p>Hostname: ${esc(device.hostname)}</p>` : "",
    device.owner ? `<p>Owner: ${esc(device.owner)}</p>` : "",
    device.location ? `<p>Location: ${esc(device.location)}</p>` : "",
    device.criticality ? `<p>Criticality: ${esc(device.criticality)}</p>` : "",
    Array.isArray(device.tags) && device.tags.length
      ? `<p>Tags: ${device.tags.map((tag) => esc(tag)).join(", ")}</p>`
      : "",
    device.notes ? `<p>Notes: ${esc(device.notes)}</p>` : "",
    switchPortLine(device),
  ].join("");
  return `<article class="device ${device.trusted ? "" : "unknown"}">
    <h2>${name} ${trustBadge}</h2>
    ${kind ? `<p class="kind" title="${esc(device.kind_reason || "")}">${esc(kind)}${announced ? ` &middot; ${esc(announced)}` : ""}</p>` : ""}
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
    ${isRandomizedMac(mac) ? "<p class='hint'>This MAC address looks randomized (a private Wi-Fi address). If this device changes it, it will show up as a new device and need trusting again.</p>" : ""}
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
  bindDeviceActions(el);
}

function bindDeviceActions(el) {
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
  refreshMapIfShown();
  $("report-link").href = viewingId === null
    ? "/api/report?format=html"
    : `/api/report?format=html&scan_id=${encodeURIComponent(viewingId)}`;
}

async function saveTrust(mac, trusted, btn) {
  // The same device can be on a card and in the map's detail panel. Use the
  // label box next to the button that was pressed.
  const card = btn.closest("article");
  const input = (card || document).querySelector(`[data-label-for="${CSS.escape(mac)}"]`);
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
  return data;
}

// A scan runs on the server in the background. Poll until it stops running.
const SCAN_POLL_MS = 2000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForScan() {
  for (;;) {
    const job = await api("/api/scan");
    if (job.state !== "running") return job;
    await sleep(SCAN_POLL_MS);
  }
}

async function watchScan() {
  setBusy(true);
  setMessage("Scanning. This can take a minute on a /24.");
  try {
    const job = await waitForScan();
    if (job.state === "error") throw new Error(job.error || "The scan failed.");
    const data = await loadLatest();
    await loadHistory();
    setMessage(`Scan done: ${data.scan.devices.length} devices.`);
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    setBusy(false);
  }
}

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  try {
    await postJson("/api/scan", { subnet: $("subnet").value.trim() || undefined });
  } catch (err) {
    setMessage(err.message, true);
    setBusy(false);
    return;
  }
  await watchScan();
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

$("search").addEventListener("input", () => { renderDevices(); refreshMapIfShown(); });
$("filter").addEventListener("change", () => { renderDevices(); refreshMapIfShown(); });
$("history").addEventListener("change", async (event) => {
  try {
    await loadScanById(event.target.value);
    setMessage("");
  } catch (err) {
    setMessage(err.message, true);
  }
});

// ---------------------------------------------------------------------------
// Map tab: the router in the middle, devices grouped by kind around it, or,
// when switches were read, by the switch they were seen on. Built with DOM
// calls and textContent only, so no device-supplied text is ever parsed as
// markup. In the kind view lines mean "reached through the router", not cables.
// ---------------------------------------------------------------------------

const SVG_NS = "http://www.w3.org/2000/svg";
const MAP_KIND_ORDER = ["network", "server", "nas", "computer", "phone", "media",
  "smart_home", "camera", "printer", "other", "unknown"];
const MAP_GLYPH = {
  router: "R", network: "N", computer: "PC", server: "SV", nas: "NAS", printer: "PR",
  camera: "CAM", media: "TV", smart_home: "IoT", phone: "PH", other: "?", unknown: "?",
};
let mapSelected = null;

function svgEl(name, attrs, text) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attrs || {})) el.setAttribute(key, String(value));
  if (text !== undefined) el.textContent = text;
  return el;
}

function shortText(value, max) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function deviceKey(device) {
  return device.mac || device.ip;
}

function mapNode(device, x, y, kind, network) {
  const worst = worstSeverity(device) || "none";
  const isRouter = kind === "router";
  const isLocal = Boolean(network.local_ip) && device.ip === network.local_ip;
  const classes = ["map-node", `sev-${worst}`, device.trusted ? "trusted" : "untrusted"];
  if (!deviceMatches(device)) classes.push("dim");
  if (mapSelected === deviceKey(device)) classes.push("selected");
  const label = displayName(device);
  const g = svgEl("g", {
    class: classes.join(" "), transform: `translate(${x.toFixed(1)} ${y.toFixed(1)})`,
    tabindex: 0, role: "button",
    "aria-label": `${KIND_LABELS[device.kind] || "Device"} ${label} ${device.ip}, worst risk ${worst}`,
  });
  g.dataset.key = deviceKey(device);
  const r = isRouter ? 30 : 20;
  if (isLocal) g.appendChild(svgEl("circle", { class: "map-you", r: r + 7 }));
  g.appendChild(svgEl("circle", { class: "map-dot", r }));
  g.appendChild(svgEl("text", { class: "map-glyph", "text-anchor": "middle", dy: "0.35em" },
    MAP_GLYPH[isRouter ? "router" : (device.kind || "unknown")] || "?"));
  g.appendChild(svgEl("text", { class: "map-label", "text-anchor": "middle", y: r + 15 }, shortText(label, 20)));
  if (isLocal) {
    g.appendChild(svgEl("text", { class: "map-sublabel", "text-anchor": "middle", y: r + 28 }, "this computer"));
  } else if (label !== device.ip) {
    g.appendChild(svgEl("text", { class: "map-sublabel", "text-anchor": "middle", y: r + 28 }, device.ip));
  }
  const reason = device.kind_reason ? ` - ${device.kind_reason}` : "";
  g.appendChild(svgEl("title", {}, `${label} (${device.ip})${reason}`));
  return g;
}

// Draw only while the Map tab is open; showTab draws it when it opens.
function refreshMapIfShown() {
  if (!$("map").hidden) renderMap();
}

// Place groups of devices in wedges around the centre. Each group gets a hub
// on an inner ring and its devices on rings outside it.
function wedgeLayout(groups, total) {
  const hubRadius = 130;
  const ringStart = 240;
  const ringGap = 92; // node plus its two label lines
  const nodeGap = 104; // arc length between neighbours: room for a 20-character label
  const minSpan = groups.length > 1 ? 0.35 : Math.PI * 2;
  // Give small groups a minimum wedge, then scale everything back to a circle.
  const raw = groups.map((g) => Math.max((Math.max(g.items.length, 1) / Math.max(1, total)) * Math.PI * 2, minSpan));
  const scale = (Math.PI * 2) / raw.reduce((a, b) => a + b, 0);
  const placed = [];
  const hubs = [];
  let angle = -Math.PI / 2;
  let maxRadius = ringStart;
  groups.forEach((group, gi) => {
    const span = raw[gi] * scale;
    const mid = angle + span / 2;
    hubs.push({ ...group, count: group.items.length,
      x: Math.cos(mid) * hubRadius, y: Math.sin(mid) * hubRadius, angle: mid });
    let index = 0;
    let ring = 0;
    while (index < group.items.length) {
      const radius = ringStart + ring * ringGap;
      const fit = Math.max(1, Math.floor((span * radius) / nodeGap));
      const row = group.items.slice(index, index + fit);
      // Odd rings sit half a slot over, so labels do not stack on the ring inside.
      const shift = ring % 2 ? 0.5 : 0;
      row.forEach((device, i) => {
        const slot = Math.min(row.length, fit);
        const a = row.length === 1 && !shift ? mid : angle + span * ((i + 0.5 + shift) / (slot + shift));
        placed.push({ device, kind: group.kind || device.kind, x: Math.cos(a) * radius, y: Math.sin(a) * radius, hub: gi });
      });
      maxRadius = Math.max(maxRadius, radius);
      index += row.length;
      ring += 1;
    }
    angle += span;
  });
  return { hubs, placed, radius: maxRadius + 70 };
}

function mapLayout(devices, gatewayIp) {
  const router = devices.find((d) => d.ip === gatewayIp) || null;
  const others = devices.filter((d) => d !== router);
  const known = new Set(MAP_KIND_ORDER);
  const kindOf = (d) => (known.has(d.kind) ? d.kind : (d.kind ? "other" : "unknown"));
  const groups = MAP_KIND_ORDER
    .map((kind) => ({ kind, label: KIND_LABELS[kind] || kind, items: others.filter((d) => kindOf(d) === kind) }))
    .filter((g) => g.items.length);
  return { router, ...wedgeLayout(groups, others.length) };
}

// Switches that answered, top of the tree first.
function answeredSwitches(scan) {
  const topo = scan && scan.topology;
  if (!topo || !Array.isArray(topo.switches)) return [];
  return topo.switches.filter((s) => !s.error)
    .sort((a, b) => (a.depth - b.depth) || String(a.name || a.ip).localeCompare(String(b.name || b.ip)));
}

// By switch: one wedge per switch that answered, plus one for devices no
// switch saw. A switch hub hangs off the router or off its parent switch.
function switchLayout(devices, gatewayIp, switches) {
  const router = devices.find((d) => d.ip === gatewayIp) || null;
  const switchIps = new Set(switches.map((s) => s.ip));
  const leaves = devices.filter((d) => d !== router && !d.is_switch && !switchIps.has(d.ip));
  const ordered = [];
  const visit = (s) => {
    ordered.push(s);
    switches.filter((c) => c.parent === s.ip).forEach(visit);
  };
  switches.filter((s) => !s.parent || !switches.some((p) => p.ip === s.parent)).forEach(visit);
  const groups = ordered.map((s) => ({
    switchInfo: s,
    label: s.name || s.ip,
    device: devices.find((d) => d.ip === s.ip) || null,
    items: leaves.filter((d) => d.switch_port && d.switch_port.switch === s.ip),
  }));
  const loose = leaves.filter((d) => !d.switch_port || !switchIps.has(d.switch_port.switch));
  if (loose.length) groups.push({ label: "Not seen on a switch", items: loose, loose: true });
  return { router, ...wedgeLayout(groups, leaves.length) };
}

function mapMode() {
  try { return sessionStorage.getItem("lantern-map-mode") === "kind" ? "kind" : "switch"; } catch (err) { return "switch"; }
}

function setMapMode(mode) {
  try { sessionStorage.setItem("lantern-map-mode", mode); } catch (err) { /* storage blocked */ }
  renderMap();
}

function switchNode(hub) {
  const s = hub.switchInfo;
  const g = svgEl("g", {
    class: "map-switch", transform: `translate(${hub.x.toFixed(1)} ${hub.y.toFixed(1)})`,
    tabindex: 0, role: "button", "aria-label": `Switch ${hub.label} ${s.ip}, ${hub.count} devices`,
  });
  g.dataset.switch = s.ip;
  g.appendChild(svgEl("rect", { x: -26, y: -15, width: 52, height: 30, rx: 6 }));
  g.appendChild(svgEl("text", { class: "map-glyph", "text-anchor": "middle", dy: "0.35em" }, "SW"));
  g.appendChild(svgEl("text", { class: "map-label", "text-anchor": "middle", y: 30 }, shortText(hub.label, 22)));
  g.appendChild(svgEl("text", { class: "map-sublabel", "text-anchor": "middle", y: 43 }, s.ip));
  g.appendChild(svgEl("title", {}, `${hub.label} (${s.ip})${s.description ? ` - ${s.description}` : ""}`));
  return g;
}

function renderMap() {
  const holder = $("map-svg");
  if (!holder) return;
  holder.textContent = "";
  $("map-legend").textContent = "";
  const switches = answeredSwitches(currentScan);
  const modeBox = $("map-mode");
  if (modeBox) {
    modeBox.hidden = !switches.length;
    for (const b of modeBox.querySelectorAll ? modeBox.querySelectorAll("button") : []) {
      b.setAttribute("aria-pressed", String(b.dataset.mode === mapMode()));
    }
  }
  if (!currentScan || !currentScan.devices.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = currentScan ? "This scan found no devices." : "No scans yet. Run the demo or a scan to draw the map.";
    holder.appendChild(p);
    showMapDetail(null);
    return;
  }
  const network = currentScan.network || {};
  const bySwitch = switches.length > 0 && mapMode() === "switch";
  const layout = bySwitch
    ? switchLayout(currentScan.devices, network.gateway_ip, switches)
    : mapLayout(currentScan.devices, network.gateway_ip);
  $("map-note").textContent = bySwitch
    ? "Lines show the switch port each device was seen on, read from the switches' MAC address tables. "
      + "A dashed line means several devices share that port, usually a Wi-Fi access point or an unmanaged switch."
    : "Lines show what each device reaches through the router, grouped by device type. They are not cables: "
      + "a scan cannot see switches or which Wi-Fi access point a device uses.";
  const size = layout.radius * 2;
  const svg = svgEl("svg", {
    viewBox: `${-layout.radius} ${-layout.radius} ${size} ${size}`,
    class: "map-drawing", role: "group",
    "aria-label": `Network map of ${currentScan.subnet}, ${currentScan.devices.length} devices`,
  });
  const lines = svgEl("g", { class: "map-lines" });
  const nodes = svgEl("g", { class: "map-nodes" });
  svg.append(lines, nodes);

  const hubAt = {};
  layout.hubs.forEach((hub) => { if (hub.switchInfo) hubAt[hub.switchInfo.ip] = hub; });
  for (const hub of layout.hubs) {
    const parent = hub.switchInfo && hub.switchInfo.parent ? hubAt[hub.switchInfo.parent] : null;
    if (parent) {
      // Switch to switch: an arc along the hub ring, so the link never
      // looks like it goes through the router in the middle.
      const r = Math.hypot(hub.x, hub.y);
      let turn = hub.angle - parent.angle;
      while (turn > Math.PI) turn -= Math.PI * 2;
      while (turn < -Math.PI) turn += Math.PI * 2;
      const sweep = turn >= 0 ? 1 : 0;
      lines.appendChild(svgEl("path", {
        class: "map-trunk uplink", fill: "none",
        d: `M ${parent.x.toFixed(1)} ${parent.y.toFixed(1)} A ${r.toFixed(1)} ${r.toFixed(1)} 0 0 ${sweep} ${hub.x.toFixed(1)} ${hub.y.toFixed(1)}`,
      }));
      continue;
    }
    const cls = hub.loose ? "map-trunk loose" : (hub.switchInfo ? "map-trunk uplink" : "map-trunk");
    lines.appendChild(svgEl("line", { class: cls, x1: 0, y1: 0, x2: hub.x.toFixed(1), y2: hub.y.toFixed(1) }));
  }
  for (const item of layout.placed) {
    const hub = layout.hubs[item.hub];
    const classes = ["map-link"];
    if (!deviceMatches(item.device)) classes.push("dim");
    if (bySwitch && item.device.switch_port && item.device.switch_port.shared) classes.push("shared");
    lines.appendChild(svgEl("line", {
      class: classes.join(" "), x1: hub.x.toFixed(1), y1: hub.y.toFixed(1), x2: item.x.toFixed(1), y2: item.y.toFixed(1),
    }));
  }
  for (const hub of layout.hubs) {
    if (hub.switchInfo) {
      nodes.appendChild(switchNode(hub));
      continue;
    }
    const g = svgEl("g", { class: "map-hub", transform: `translate(${hub.x.toFixed(1)} ${hub.y.toFixed(1)})` });
    g.appendChild(svgEl("circle", { r: 6 }));
    const cos = Math.cos(hub.angle);
    const anchor = cos < -0.3 ? "end" : (cos > 0.3 ? "start" : "middle");
    const dx = anchor === "end" ? -10 : (anchor === "start" ? 10 : 0);
    const dy = anchor === "middle" ? (Math.sin(hub.angle) < 0 ? -12 : 20) : 4;
    g.appendChild(svgEl("text", { class: "map-hub-label", "text-anchor": anchor, x: dx, y: dy },
      `${hub.label} (${hub.count})`));
    nodes.appendChild(g);
  }
  if (layout.router) {
    nodes.appendChild(mapNode(layout.router, 0, 0, "router", network));
  } else {
    const g = svgEl("g", { class: "map-node map-virtual" });
    g.appendChild(svgEl("circle", { class: "map-dot", r: 30 }));
    g.appendChild(svgEl("text", { class: "map-glyph", "text-anchor": "middle", dy: "0.35em" }, "?"));
    g.appendChild(svgEl("text", { class: "map-label", "text-anchor": "middle", y: 46 }, "Router not found"));
    g.appendChild(svgEl("text", { class: "map-sublabel", "text-anchor": "middle", y: 59 }, currentScan.subnet));
    nodes.appendChild(g);
  }
  for (const item of layout.placed) nodes.appendChild(mapNode(item.device, item.x, item.y, item.kind, network));

  const activate = (target) => {
    const node = target.closest("[data-key]");
    if (node) { selectMapDevice(node.dataset.key); return true; }
    const sw = target.closest("[data-switch]");
    if (sw) { selectMapSwitch(sw.dataset.switch); return true; }
    return false;
  };
  svg.addEventListener("click", (event) => { activate(event.target); });
  svg.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    if (activate(event.target)) event.preventDefault();
  });
  holder.appendChild(svg);
  renderMapLegend(network, bySwitch);
  const selected = currentScan.devices.find((d) => deviceKey(d) === mapSelected);
  showMapDetail(selected || null);
}

function renderMapLegend(network, bySwitch) {
  const legend = $("map-legend");
  const items = [
    ["sev-critical", "Critical risk"], ["sev-high", "High risk"], ["sev-medium", "Medium risk"],
    ["sev-low", "Low risk"], ["sev-none", "No risky ports"], ["untrusted", "Dashed ring: not trusted yet"],
  ];
  if (bySwitch) {
    items.push(["", "Dashed line: a shared port (Wi-Fi or an unmanaged switch)"]);
    const topo = currentScan.topology || {};
    const failed = (topo.switches || []).filter((s) => s.error).length;
    if (failed) items.push(["", `${failed} switch(es) did not answer`]);
  }
  if (network.gateway_guessed) items.push(["", "Router guessed from its ports and address"]);
  for (const [cls, text] of items) {
    const li = document.createElement("li");
    if (cls) {
      const swatch = document.createElement("span");
      swatch.className = `swatch ${cls}`;
      li.appendChild(swatch);
    }
    li.appendChild(document.createTextNode(text));
    legend.appendChild(li);
  }
}

function selectMapSwitch(ip) {
  const topo = (currentScan && currentScan.topology) || {};
  const s = (topo.switches || []).find((item) => item.ip === ip);
  const device = currentScan && currentScan.devices.find((d) => d.ip === ip);
  if (device) { selectMapDevice(deviceKey(device)); return; }
  mapSelected = null;
  document.querySelectorAll("#map-svg .map-node").forEach((node) => node.classList.remove("selected"));
  const panel = $("map-detail");
  if (!s) { showMapDetail(null); return; }
  const parent = s.parent ? (topo.switches || []).find((item) => item.ip === s.parent) : null;
  const up = parent
    ? `Uplink ${s.port_to_parent || "?"} to ${parent.name || parent.ip}, ${s.parent_port || "?"}`
    : (s.port_to_parent ? `Router on ${s.port_to_parent}` : "");
  panel.innerHTML = `<article class="device">
    <h2>${esc(s.name || s.ip)} <span class="badge">switch</span></h2>
    <p class="meta">${esc(s.ip)}</p>
    ${s.description ? `<p>${esc(s.description)}</p>` : ""}
    ${up ? `<p>${esc(up)}</p>` : ""}
    <p class="hint">This switch's management address did not show up in the scan, so it has no device card.</p>
  </article>`;
}

function selectMapDevice(key) {
  mapSelected = key;
  document.querySelectorAll("#map-svg .map-node").forEach((node) => {
    node.classList.toggle("selected", node.dataset.key === key);
  });
  const device = currentScan && currentScan.devices.find((d) => deviceKey(d) === key);
  showMapDetail(device || null);
}

function showMapDetail(device) {
  const panel = $("map-detail");
  if (!device) {
    panel.innerHTML = `<p class="hint">Select a device on the map to see its details.</p>`;
    return;
  }
  // renderDevice escapes every field, the same as the Devices tab.
  panel.innerHTML = renderDevice(device);
  bindDeviceActions(panel);
}

function showTab(name) {
  const mapOn = name === "map";
  $("tab-devices").setAttribute("aria-selected", String(!mapOn));
  $("tab-map").setAttribute("aria-selected", String(mapOn));
  $("tab-devices").tabIndex = mapOn ? -1 : 0;
  $("tab-map").tabIndex = mapOn ? 0 : -1;
  $("devices").hidden = mapOn;
  $("map").hidden = !mapOn;
  try { sessionStorage.setItem("lantern-tab", name); } catch (err) { /* storage blocked */ }
  if (mapOn) renderMap();
}

$("tab-devices").addEventListener("click", () => showTab("devices"));
$("map-mode").addEventListener("click", (event) => {
  const button = event.target.closest && event.target.closest("button[data-mode]");
  if (button) setMapMode(button.dataset.mode);
});
$("tab-map").addEventListener("click", () => showTab("map"));
$("tabs").addEventListener("keydown", (event) => {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  const next = $("tab-map").getAttribute("aria-selected") === "true" ? "devices" : "map";
  showTab(next);
  $(next === "map" ? "tab-map" : "tab-devices").focus();
});
try {
  if (sessionStorage.getItem("lantern-tab") === "map") showTab("map");
} catch (err) { /* storage blocked */ }

async function startDashboard() {
  try {
    const status = await loadStatus();
    await loadLatest();
    await loadHistory();
    // A scan started from another tab or before a reload is still running.
    if (status.scan_running) watchScan();
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
