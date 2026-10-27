"use strict";

const $ = (id) => document.getElementById(id);
let currentScan = null;
let currentDiff = null;
let viewingLatest = true;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function worstSeverity(device) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  let worst = null;
  for (const f of device.findings || []) {
    if (!worst || order[f.severity] < order[worst]) worst = f.severity;
  }
  return worst;
}

function setMessage(text, isError) {
  const el = $("message");
  el.textContent = text || "";
  el.className = isError ? "message error" : "message";
}

async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function renderSummary(scan, diff) {
  const el = $("summary");
  if (!scan) {
    el.innerHTML = "";
    return;
  }
  const critical = scan.devices.filter((d) => worstSeverity(d) === "critical").length;
  const high = scan.devices.filter((d) => worstSeverity(d) === "high").length;
  const unknown = scan.devices.filter((d) => !d.trusted).length;
  const added = diff ? diff.added.length : 0;
  el.innerHTML = `
    <div class="stat"><b>${scan.devices.length}</b><span>devices</span></div>
    <div class="stat ${added ? "warn" : ""}"><b>${added}</b><span>new since last scan</span></div>
    <div class="stat ${unknown ? "warn" : ""}"><b>${unknown}</b><span>unknown / untrusted</span></div>
    <div class="stat ${critical ? "bad" : ""}"><b>${critical}</b><span>critical devices</span></div>
    <div class="stat ${high ? "warn" : ""}"><b>${high}</b><span>high-risk devices</span></div>`;
  $("status").textContent = `${scan.subnet} | ${new Date(scan.started_at).toLocaleString()}${scan.demo ? " | demo" : ""}`;
}

function renderDiff(scan, diff) {
  const el = $("diff");
  if (!scan || !diff) {
    el.className = "diff calm";
    el.innerHTML = "<h2>What changed</h2><p>Run two scans to see what changed. The demo does this for you.</p>";
    return;
  }
  const changed = diff.changed.length;
  const calm = diff.added.length === 0 && diff.removed.length === 0 && changed === 0;
  el.className = calm ? "diff calm" : "diff";
  const added = diff.added.map((d) => esc(d.ip)).join(", ") || "none";
  const removed = diff.removed.map((d) => esc(d.ip)).join(", ") || "none";
  const changedText = diff.changed.map((c) =>
    `${esc(c.device.ip)} opened [${c.opened.join(", ")}], closed [${c.closed.join(", ")}]`
  ).join("; ") || "none";
  el.innerHTML = `<h2>What changed since the last scan</h2>
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
  const hay = [device.ip, device.mac, device.hostname, device.label].join(" ").toLowerCase();
  return hay.includes(q);
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
  el.innerHTML = devices.map((device) => {
    const name = esc(device.label || device.hostname || device.ip);
    const worst = worstSeverity(device);
    const ports = device.open_ports.map((p) => `<span class="port">${p.port}</span>`).join("") || "<span class='port'>none</span>";
    const findings = (device.findings || []).map((f) => `
      <li><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
      <strong> ${f.port} ${esc(f.service)}:</strong> ${esc(f.title)}
      <small>${esc(f.fix)}</small></li>`).join("") || "<li>No risky open ports found.</li>";
    const trustBadge = device.trusted
      ? `<span class="badge trusted">trusted</span>`
      : `<span class="badge unknown">unknown</span>`;
    const mac = device.mac || "";
    return `<article class="device ${device.trusted ? "" : "unknown"}">
      <h2>${name} ${trustBadge}</h2>
      <p class="meta">${esc(device.ip)}${mac ? ` &middot; ${esc(mac)}` : ""}${device.hostname ? ` &middot; ${esc(device.hostname)}` : ""}</p>
      ${worst ? `<p>Worst risk: <span class="badge ${esc(worst)}">${esc(worst)}</span></p>` : ""}
      <div class="ports">${ports}</div>
      <ul class="findings">${findings}</ul>
      <div class="trust-row">
        <input data-label-for="${esc(mac)}" value="${esc(device.label || "")}" placeholder="Label, e.g. Living room TV" ${mac ? "" : "disabled"} aria-label="Label for ${esc(device.ip)}">
        <button class="secondary" data-trust="${esc(mac)}" ${mac ? "" : "disabled"}>Trust</button>
        <button class="secondary" data-untrust="${esc(mac)}" ${mac ? "" : "disabled"}>Mark unknown</button>
      </div>
      ${mac ? "" : "<p class='hint'>No MAC address, so this device cannot be trusted yet. It will be keyed by IP only.</p>"}
    </article>`;
  }).join("");

  el.querySelectorAll("[data-trust]").forEach((btn) => {
    btn.addEventListener("click", () => saveTrust(btn.dataset.trust, true, btn));
  });
  el.querySelectorAll("[data-untrust]").forEach((btn) => {
    btn.addEventListener("click", () => saveTrust(btn.dataset.untrust, false, btn));
  });
}

async function saveTrust(mac, trusted, btn) {
  const input = document.querySelector(`[data-label-for="${CSS.escape(mac)}"]`);
  const label = input ? input.value.trim() : "";
  btn.disabled = true;
  try {
    await api("/api/trust", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mac, label, trusted }),
    });
    setMessage(trusted ? `Trusted ${mac}${label ? ` as ${label}` : ""}.` : `Marked ${mac} unknown.`);
    await loadLatest(true);
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

async function loadHistory() {
  try {
    const data = await api("/api/scans");
    const select = $("history");
    const current = select.value;
    select.innerHTML = `<option value="">Latest scan</option>` + data.scans.map((s) =>
      `<option value="${s.id}">#${s.id} ${esc(new Date(s.started_at).toLocaleString())} (${s.device_count} devices)${s.demo ? " demo" : ""}</option>`
    ).join("");
    select.value = current;
  } catch (err) {
    setMessage(err.message, true);
  }
}

async function loadLatest(keepHistorySelection) {
  const data = await api("/api/scans/latest");
  currentScan = data.scan;
  currentDiff = data.diff;
  viewingLatest = true;
  renderSummary(currentScan, currentDiff);
  renderDiff(currentScan, currentDiff);
  renderDevices();
  if (!keepHistorySelection) await loadHistory();
  return data;
}

async function loadScanById(id) {
  if (!id) {
    viewingLatest = true;
    await loadLatest(true);
    return;
  }
  viewingLatest = false;
  const data = await api(`/api/scans/${id}`);
  currentScan = data.scan;
  currentDiff = null;
  renderSummary(currentScan, null);
  renderDiff(currentScan, null);
  renderDevices();
  $("report-link").href = `/api/report?format=html&scan_id=${id}`;
}

async function loadStatus() {
  const data = await api("/api/status");
  if (data.guessed_subnet && !$("subnet").value) $("subnet").value = data.guessed_subnet;
  return data;
}

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const btn = $("scan-btn");
  btn.disabled = true;
  setMessage("Scanning. This can take a minute on a /24.");
  try {
    const data = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subnet: $("subnet").value.trim() || undefined }),
    });
    currentScan = data.scan;
    currentDiff = data.diff;
    viewingLatest = true;
    renderSummary(currentScan, currentDiff);
    renderDiff(currentScan, currentDiff);
    renderDevices();
    await loadHistory();
    setMessage(`Scan done: ${currentScan.devices.length} devices.`);
  } catch (err) {
    setMessage(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

$("demo-btn").addEventListener("click", async () => {
  setMessage("Running demo scans.");
  try {
    await api("/api/demo", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    await loadLatest();
    setMessage("Demo done. Look for the new device with Telnet open.");
  } catch (err) {
    setMessage(err.message, true);
  }
});

$("refresh-btn").addEventListener("click", async () => {
  try {
    if (viewingLatest) await loadLatest();
    else await loadScanById($("history").value);
    setMessage("");
  } catch (err) {
    setMessage(err.message, true);
  }
});

$("search").addEventListener("input", renderDevices);
$("filter").addEventListener("change", renderDevices);
$("history").addEventListener("change", (event) => loadScanById(event.target.value));

(async () => {
  try {
    await loadStatus();
    await loadLatest();
  } catch (err) {
    $("status").textContent = "Could not reach the Lantern server.";
    setMessage(err.message, true);
  }
})();
