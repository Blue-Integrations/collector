const $ = (id) => document.getElementById(id);

const PROTOS = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6" };

let lastOverview = null;
let formsSyncedOnce = false;
let lastFlowsKey = "";
let lastVendorPick = "";
let routerProfiles = {};

try {
  const profilesNode = document.getElementById("router-profiles-data");
  if (profilesNode?.textContent) {
    routerProfiles = JSON.parse(profilesNode.textContent);
  }
} catch {
  routerProfiles = {};
}

function getRouterProfile(vendor) {
  return lastOverview?.router_profiles?.[vendor] || routerProfiles[vendor] || null;
}

function formatEnvKeys(profile) {
  return (profile?.env_keys || []).map((k) => `  • ${k}`).join("\n");
}

function formatMissingVendorMessage(profile) {
  const label = profile?.label || profile?.vendor || "router";
  const missing = (profile?.missing || []).length
    ? profile.missing.map((k) => `  • ${k}`).join("\n")
    : "  • required .env settings";
  return (
    `Cannot switch to ${label} — .env is not configured for that router.\n\n` +
    `Missing:\n${missing}\n\n` +
    `Set these in .env and restart the collector:\n${formatEnvKeys(profile)}`
  );
}

function vendorSwitchMessage(fromVendor, toVendor, profile) {
  const labels = { mikrotik: "MikroTik", cisco: "Cisco", juniper: "Juniper" };
  const from = labels[fromVendor] || fromVendor;
  const to = profile?.label || labels[toVendor] || toVendor;
  let msg = `Switch router blocker from ${from} to ${to}?\n\n`;
  msg += `Uses .env settings for ${to}:\n${formatEnvKeys(profile)}\n\n`;
  if (profile?.host) {
    msg += `Current .env target: ${profile.host}:${profile.port}\n\n`;
  }
  msg += "Block, unblock, and Test SSH will use the selected router.";
  return msg;
}

function panelVisible(id) {
  const el = $(id);
  return el && !el.classList.contains("hidden");
}

function settingsModalOpen() {
  return panelVisible("settings-modal");
}

function hydrateSettingsForms(data) {
  if (!data.thresholds) return;
  $("s-window").value = data.thresholds.scan_window_sec;
  $("s-vertical").value = data.thresholds.vertical_port_threshold;
  $("s-horizontal").value = data.thresholds.horizontal_host_threshold;
  $("s-spray").value = data.thresholds.unique_port_threshold;
  $("s-icmp").value = data.thresholds.icmp_flood_threshold;
  $("s-large-bytes").value = data.thresholds.large_flow_min_bytes;
  $("s-large-count").value = data.thresholds.large_flow_threshold;
  $("s-allow").value = data.thresholds.allowlist;
  const builtins = $("allowlist-builtins");
  if (builtins) {
    const dns = (data.thresholds.public_dns || []).join(", ");
    builtins.textContent = dns
      ? `Built-in public DNS resolvers (always allowlisted): ${dns}`
      : "";
  }
}

function hydrateWebhookForms(data) {
  if (!data.webhooks) return;
  $("w-slack").value = data.webhooks.slack_webhook_url || "";
  $("w-discord").value = data.webhooks.discord_webhook_url || "";
  $("w-notify-detections").checked = !!data.webhooks.webhook_notify_detections;
  $("w-notify-blocks").checked = !!data.webhooks.webhook_notify_blocks;
}

function hydrateAllSettingsForms(data) {
  hydrateSettingsForms(data);
  hydrateWebhookForms(data);
  if (data.version != null) {
    $("upgrade-line").textContent = `Version ${data.version || "?"}`;
  }
}

function updateToolbarControls(data, vendor) {
  const vendorPick = $("vendor-pick");
  if (vendorPick && document.activeElement !== vendorPick && vendorPick.value !== vendor) {
    vendorPick.value = vendor;
  }
  const autoBlock = $("auto-block");
  if (autoBlock && document.activeElement !== autoBlock) {
    autoBlock.checked = !!data.auto_block;
  }
}

function flowsSignature(rows) {
  return rows
    .map((row) => `${row.src_ip}:${row.src_port}|${row.dst_ip}:${row.dst_port}|${row.proto}|${row.bytes}`)
    .join("\n");
}

function withScrollPreserved(container, render) {
  const top = container ? container.scrollTop : 0;
  render();
  if (container) container.scrollTop = top;
}

function fmt(n) {
  if (n == null) return "0";
  return Number(n).toLocaleString();
}

function age(ts, now) {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(now - ts));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}

function detailText(row) {
  const d = row.detail || {};
  if (row.kind === "vertical") {
    return `${d.unique_ports || row.score} ports on ${d.target || "host"}`;
  }
  if (row.kind === "horizontal") {
    return `${d.unique_hosts || row.score} hosts on :${d.port}`;
  }
  if (row.kind === "connect-storm") {
    return `${d.unique_src_ports || row.score} src-ports → ${d.target}:${d.port}`;
  }
  if (row.kind === "icmp-flood") {
    return `${d.flows || row.score} ICMP flows · max ${fmt(d.max_bytes)} B → ${d.sample_targets?.[0] || "?"}`;
  }
  if (row.kind === "large-flow") {
    return `${d.flows || row.score} flows ≥ ${fmt(d.min_bytes)} B · max ${fmt(d.max_bytes)} B`;
  }
  return `${d.unique_ports || row.score} ports / ${d.unique_hosts || "?"} hosts`;
}

function parseDetail(row) {
  const d = row.detail;
  if (d && typeof d === "object") return d;
  try {
    return JSON.parse(d || "{}");
  } catch {
    return {};
  }
}

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const v = Number(part);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) + v;
  }
  return n >>> 0;
}

function ipInCidr(ip, cidr) {
  if (!cidr || !ip) return false;
  const [net, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  if (!net || !Number.isInteger(bits)) return ip === net;
  if (ip.includes(":")) {
    if (!net.includes(":")) return false;
    return ip.toLowerCase().startsWith(net.toLowerCase().split("::")[0]);
  }
  const addr = ipv4ToInt(ip);
  const network = ipv4ToInt(net);
  if (addr == null || network == null) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (addr & mask) === (network & mask);
}

function ipInAnyCidr(ip, cidrs) {
  return (cidrs || []).some((cidr) => ipInCidr(ip, cidr));
}

function buildAllowNets(allowlist) {
  return (allowlist || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function filterState() {
  const portRaw = $("f-dst-port").value.trim();
  return {
    proto: $("f-proto").value,
    kind: $("f-kind").value,
    dstPort: portRaw === "" ? null : Number(portRaw),
    protectedOnly: $("f-protected").checked,
    synOnly: $("f-syn").checked,
    hideBlocked: $("f-hide-blocked").checked,
    hideAllowlisted: $("f-hide-allow").checked,
  };
}

function isAllowlisted(ip, allowNets, protectedNets, publicDns) {
  return (
    ipInAnyCidr(ip, allowNets)
    || ipInAnyCidr(ip, protectedNets)
    || ipInAnyCidr(ip, publicDns)
  );
}

function isBlocked(ip, blockedSet) {
  return blockedSet.has(ip);
}

function allowlistFilterTitle(thresholds) {
  if (!thresholds) {
    return "Hides flows and detections whose source IP is allowlisted.";
  }
  const parts = [];
  const allow = (thresholds.allowlist || "").trim();
  if (allow) {
    parts.push(`LAN / manual allowlist: ${allow}`);
  }
  const protectedNets = (thresholds.protected || []).join(", ");
  if (protectedNets) {
    parts.push(`Protected WAN: ${protectedNets}`);
  }
  const dns = (thresholds.public_dns || []).join(", ");
  if (dns) {
    parts.push(`Public DNS resolvers (built-in): ${dns}`);
  }
  if (!parts.length) {
    return "Hides flows and detections whose source IP is allowlisted.";
  }
  return `When checked, hides rows whose source IP is in: ${parts.join(" · ")}`;
}

function updateAllowlistFilterTitle(thresholds) {
  const label = $("f-hide-allow-label");
  if (!label) return;
  label.title = allowlistFilterTitle(thresholds);
}

function detectionMatchesPort(row, dstPort) {
  if (dstPort == null) return true;
  const d = parseDetail(row);
  if (row.kind === "horizontal" || row.kind === "connect-storm") {
    return Number(d.port) === dstPort;
  }
  if (row.kind === "vertical" || row.kind === "spray") {
    return false;
  }
  return Number(d.port) === dstPort;
}

function detectionTarget(row) {
  const d = parseDetail(row);
  return d.target || "";
}

function applyDetectionFilters(rows, data, state) {
  const blocked = new Set(data.blocked_ips || []);
  const allowNets = buildAllowNets(data.thresholds?.allowlist);
  const protectedNets = data.thresholds?.protected || [];
  const publicDns = data.thresholds?.public_dns || [];
  return rows.filter((row) => {
    if (state.hideBlocked && isBlocked(row.src_ip, blocked)) return false;
    if (state.hideAllowlisted && isAllowlisted(row.src_ip, allowNets, protectedNets, publicDns)) {
      return false;
    }
    if (state.kind && row.kind !== state.kind) return false;
    if (state.dstPort != null && !detectionMatchesPort(row, state.dstPort)) return false;
    if (state.protectedOnly) {
      const target = detectionTarget(row);
      if (!target || !ipInAnyCidr(target, protectedNets)) return false;
    }
    return true;
  });
}

function applyFlowFilters(rows, data, state) {
  const blocked = new Set(data.blocked_ips || []);
  const allowNets = buildAllowNets(data.thresholds?.allowlist);
  const protectedNets = data.thresholds?.protected || [];
  const publicDns = data.thresholds?.public_dns || [];
  return rows.filter((row) => {
    if (state.hideBlocked && isBlocked(row.src_ip, blocked)) return false;
    if (state.hideAllowlisted && isAllowlisted(row.src_ip, allowNets, protectedNets, publicDns)) {
      return false;
    }
    if (state.proto && String(row.proto) !== state.proto) return false;
    if (state.dstPort != null && Number(row.dst_port) !== state.dstPort) return false;
    if (state.protectedOnly && !ipInAnyCidr(row.dst_ip, protectedNets)) return false;
    if (state.synOnly) {
      if (Number(row.proto) !== 6) return false;
      if ((Number(row.tcp_flags) || 0) & 0x02) {
        /* SYN set */
      } else {
        return false;
      }
    }
    return true;
  });
}

function updateFilterHint(data, detShown, detTotal, flowShown, flowTotal) {
  const el = $("filter-hint");
  if (!el) return;
  const parts = [];
  if (detTotal !== detShown) {
    parts.push(`${detShown} of ${detTotal} detections`);
  } else {
    parts.push(`${detShown} detections`);
  }
  if (flowTotal !== flowShown) {
    parts.push(`${flowShown} of ${flowTotal} flows`);
  } else {
    parts.push(`${flowShown} flows`);
  }
  el.textContent = parts.join(" · ");
}

async function api(path, options) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (res.status === 401) {
    window.location = "/login";
    throw new Error("auth");
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || res.statusText);
  return body;
}

function renderOverview(data, options = {}) {
  const { syncForms = false } = options;
  lastOverview = data;
  const state = filterState();
  const s = data.stats;
  const mt = data.router || data.mikrotik;
  const vendor = data.vendor || mt.vendor || "mikrotik";
  const labels = {
    mikrotik: "MikroTik",
    cisco: "Cisco",
    juniper: "Juniper",
  };
  const vendorLabel = labels[vendor] || vendor;
  const records10s =
    typeof s.flows_last_10s === "number"
      ? s.flows_last_10s
      : Math.round((s.flows_per_sec || 0) * 10);
  $("m-rate").textContent = fmt(records10s);
  $("m-flows").textContent = fmt(s.flows);
  const filteredDetections = applyDetectionFilters(data.detections, data, state);
  $("m-scans").textContent = fmt(filteredDetections.length);
  $("m-blocks").textContent = fmt(data.blocks.length);
  if ($("det-badge")) $("det-badge").textContent = fmt(filteredDetections.length);
  if ($("block-badge")) $("block-badge").textContent = fmt(data.blocks.length);

  const probe = $("probe-pill");
  probe.textContent = s.last_flow_at
    ? `probe live · ${fmt(records10s)} in 10s · ${s.flows_per_sec}/s`
    : "probe waiting for NetFlow";
  probe.className = "pill" + (s.last_flow_at ? " ok" : "");

  const mtPill = $("mt-pill");
  mtPill.textContent = mt.connected
    ? `${vendorLabel} ${mt.identity || mt.host} · ${mt.list_count} listed`
    : `${vendorLabel} down · ${mt.host}:${mt.port}`;
  mtPill.className = "pill" + (mt.connected ? " ok" : " bad");
  $("mt-hint").textContent = mt.last_error || (mt.filter_ready ? "drop rules present" : "");
  $("list-name").textContent = `${mt.address_list || "blocked-scanners"} · click or Alt+click an IP for WHOIS`;
  $("list-heading").textContent = `${vendorLabel} access list`;
  $("auto-block-label").textContent = `Auto-block on ${vendorLabel}`;

  if (syncForms) {
    hydrateAllSettingsForms(data);
  }
  if (data.router_profiles) {
    routerProfiles = data.router_profiles;
  }
  updateToolbarControls(data, vendor);
  lastVendorPick = vendor;
  updateAllowlistFilterTitle(data.thresholds);

  const detWrap = $("panel-detections")?.querySelector(".table-wrap");
  withScrollPreserved(detWrap, () => {
    const detBody = $("detections");
    detBody.innerHTML = "";
    if (!filteredDetections.length) {
      detBody.innerHTML = `<tr><td colspan="5" class="empty">${
        data.detections.length ? "No detections match the current filters." : "No scanners in the last hour."
      }</td></tr>`;
    } else {
      for (const row of filteredDetections) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${row.src_ip}</td>
          <td><span class="kind ${row.kind}">${row.kind}</span></td>
          <td>${row.score}</td>
          <td>${detailText(row)} · ${age(row.last_seen, data.now)}</td>
          <td><button type="button" data-block="${row.src_ip}">Block</button></td>`;
        detBody.appendChild(tr);
      }
    }
  });

  const blockWrap = $("panel-blocks")?.querySelector(".table-wrap");
  withScrollPreserved(blockWrap, () => {
    const blockBody = $("blocks");
    blockBody.innerHTML = "";
    if (!data.blocks.length) {
      blockBody.innerHTML = `<tr><td colspan="5" class="empty">Nothing on the access list yet.</td></tr>`;
    } else {
      for (const row of data.blocks) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><button type="button" class="ip-whois" data-whois="${row.ip}" title="WHOIS (Alt+click)">${row.ip}</button></td>
          <td>${row.source}</td>
          <td>${row.reason}</td>
          <td>${age(row.created_at, data.now)}</td>
          <td><button type="button" class="ghost" data-unblock="${row.ip}">Unblock</button></td>`;
        blockBody.appendChild(tr);
      }
    }
  });

  const filteredFlows = applyFlowFilters(data.flows, data, state);
  const flowsKey = flowsSignature(filteredFlows);
  const flowWrap = document.querySelector(".flows-table-wrap");
  if (flowsKey !== lastFlowsKey) {
    lastFlowsKey = flowsKey;
    withScrollPreserved(flowWrap, () => {
      const flowBody = $("flows");
      flowBody.innerHTML = "";
      if (!filteredFlows.length) {
        flowBody.innerHTML = `<tr><td colspan="4" class="empty">${
          data.flows.length ? "No flows match the current filters." : "Waiting for exported flows."
        }</td></tr>`;
      } else {
        for (const row of filteredFlows) {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${row.src_ip}:${row.src_port}</td>
            <td>${row.dst_ip}:${row.dst_port}</td>
            <td>${PROTOS[row.proto] || row.proto}</td>
            <td>${fmt(row.bytes)}</td>`;
          flowBody.appendChild(tr);
        }
      }
    });
  }

  updateFilterHint(
    data,
    filteredDetections.length,
    data.detections.length,
    filteredFlows.length,
    data.flows.length
  );

  const log = $("events");
  const logHtml = data.events
    .map(
      (e) =>
        `<li class="${e.level}">${new Date(e.ts * 1000).toLocaleTimeString()}  ${e.message}</li>`
    )
    .join("");
  if (log.innerHTML !== logHtml) {
    withScrollPreserved(log, () => {
      log.innerHTML = logHtml;
    });
  }
}

function renderLiveFromCache() {
  if (lastOverview) renderOverview(lastOverview, { syncForms: false });
}

function rerenderFilters() {
  lastFlowsKey = "";
  if (lastOverview) renderOverview(lastOverview, { syncForms: false });
}

for (const id of [
  "f-proto",
  "f-kind",
  "f-dst-port",
  "f-protected",
  "f-syn",
  "f-hide-blocked",
  "f-hide-allow",
]) {
  $(id).addEventListener("change", rerenderFilters);
  if (id === "f-dst-port") {
    $(id).addEventListener("input", rerenderFilters);
  }
}

async function refresh() {
  try {
    const data = await api("/api/overview");
    renderOverview(data, { syncForms: !formsSyncedOnce });
    formsSyncedOnce = true;
  } catch (err) {
    if (err.message !== "auth") $("mt-hint").textContent = err.message;
  }
}

const WHOIS_FIELDS = [
  ["network", "Network"],
  ["cidr", "Range"],
  ["country", "Country"],
  ["org", "Organization"],
  ["abuse", "Abuse contact"],
  ["rir", "RIR"],
  ["handle", "Handle"],
];

function showWhoisModal(ip, data, hint) {
  $("whois-title").textContent = "WHOIS / RDAP";
  $("whois-ip").textContent = ip;
  $("whois-hint").textContent = hint || "";
  const body = $("whois-body");
  body.innerHTML = "";
  let any = false;
  for (const [key, label] of WHOIS_FIELDS) {
    const val = data[key];
    if (!val) continue;
    any = true;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = val;
    body.appendChild(dt);
    body.appendChild(dd);
  }
  if (!any) {
    const dd = document.createElement("dd");
    dd.className = "empty";
    dd.textContent = "No RDAP fields returned.";
    body.appendChild(dd);
  }
  $("whois-modal").classList.remove("hidden");
  $("whois-modal").setAttribute("aria-hidden", "false");
}

function hideWhoisModal() {
  $("whois-modal").classList.add("hidden");
  $("whois-modal").setAttribute("aria-hidden", "true");
}

function showSettingsModal() {
  if (lastOverview) hydrateAllSettingsForms(lastOverview);
  $("settings-modal").classList.remove("hidden");
  $("settings-modal").setAttribute("aria-hidden", "false");
}

function hideSettingsModal() {
  $("settings-modal").classList.add("hidden");
  $("settings-modal").setAttribute("aria-hidden", "true");
}

async function openWhois(ip) {
  $("whois-hint").textContent = "Looking up…";
  $("whois-modal").classList.remove("hidden");
  $("whois-ip").textContent = ip;
  $("whois-body").innerHTML = "";
  try {
    const data = await api(`/api/whois/${encodeURIComponent(ip)}`);
    showWhoisModal(ip, data, "Source: RDAP (rdap.org)");
  } catch (err) {
    showWhoisModal(ip, {}, err.message);
  }
}

$("detections").addEventListener("click", async (ev) => {
  const ip = ev.target.getAttribute("data-block");
  if (!ip) return;
  ev.target.disabled = true;
  try {
    await api("/api/block", { method: "POST", body: JSON.stringify({ ip, reason: "manual-from-detection" }) });
    await refresh();
  } catch (err) {
    alert(err.message);
  }
});

$("blocks").addEventListener("click", async (ev) => {
  const whoisIp = ev.target.getAttribute("data-whois");
  if (whoisIp) {
    ev.preventDefault();
    await openWhois(whoisIp);
    return;
  }
  const ip = ev.target.getAttribute("data-unblock");
  if (!ip) return;
  ev.target.disabled = true;
  try {
    await api("/api/unblock", { method: "POST", body: JSON.stringify({ ip }) });
    await refresh();
  } catch (err) {
    alert(err.message);
  }
});

$("whois-close").addEventListener("click", hideWhoisModal);
$("whois-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "whois-modal") hideWhoisModal();
});
$("settings-close").addEventListener("click", hideSettingsModal);
$("settings-modal").addEventListener("click", (ev) => {
  if (ev.target.id === "settings-modal") hideSettingsModal();
});
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    hideWhoisModal();
    hideSettingsModal();
  }
});

$("manual-block").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const ip = $("manual-ip").value.trim();
  try {
    await api("/api/block", { method: "POST", body: JSON.stringify({ ip, reason: "manual" }) });
    $("manual-ip").value = "";
    await refresh();
  } catch (err) {
    alert(err.message);
  }
});

$("auto-block").addEventListener("change", async (ev) => {
  try {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({ auto_block: ev.target.checked }),
    });
  } catch (err) {
    alert(err.message);
    ev.target.checked = !ev.target.checked;
  }
});

$("btn-settings").addEventListener("click", () => {
  if (settingsModalOpen()) {
    hideSettingsModal();
  } else {
    showSettingsModal();
  }
});

$("settings-panel").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({
        scan_window_sec: Number($("s-window").value),
        vertical_port_threshold: Number($("s-vertical").value),
        horizontal_host_threshold: Number($("s-horizontal").value),
        unique_port_threshold: Number($("s-spray").value),
        icmp_flood_threshold: Number($("s-icmp").value),
        large_flow_min_bytes: Number($("s-large-bytes").value),
        large_flow_threshold: Number($("s-large-count").value),
        allowlist: $("s-allow").value,
      }),
    });
    const result = await api("/api/webhooks", {
      method: "POST",
      body: JSON.stringify({
        slack_webhook_url: $("w-slack").value.trim(),
        discord_webhook_url: $("w-discord").value.trim(),
        webhook_notify_detections: $("w-notify-detections").checked,
        webhook_notify_blocks: $("w-notify-blocks").checked,
      }),
    });
    if (result.webhooks) hydrateWebhookForms({ webhooks: result.webhooks });
    $("webhook-hint").textContent = "Settings saved.";
    hideSettingsModal();
    if (lastOverview) {
      lastOverview.thresholds = {
        ...lastOverview.thresholds,
        scan_window_sec: Number($("s-window").value),
        vertical_port_threshold: Number($("s-vertical").value),
        horizontal_host_threshold: Number($("s-horizontal").value),
        unique_port_threshold: Number($("s-spray").value),
        icmp_flood_threshold: Number($("s-icmp").value),
        large_flow_min_bytes: Number($("s-large-bytes").value),
        large_flow_threshold: Number($("s-large-count").value),
        allowlist: $("s-allow").value,
      };
      lastOverview.webhooks = result.webhooks || lastOverview.webhooks;
    }
    await refresh();
  } catch (err) {
    $("webhook-hint").textContent = err.message;
    alert(err.message);
  }
});

async function testWebhook(channel) {
  const hint = $("webhook-hint");
  hint.textContent = `Testing ${channel}…`;
  try {
    await api("/api/webhooks/test", {
      method: "POST",
      body: JSON.stringify({
        channel,
        slack_webhook_url: $("w-slack").value.trim(),
        discord_webhook_url: $("w-discord").value.trim(),
      }),
    });
    hint.textContent = `${channel === "slack" ? "Slack" : "Discord"} test message sent.`;
  } catch (err) {
    hint.textContent = err.message;
    alert(err.message);
  }
}

$("w-test-slack").addEventListener("click", () => testWebhook("slack"));
$("w-test-discord").addEventListener("click", () => testWebhook("discord"));

$("btn-test").addEventListener("click", async () => {
  $("btn-test").disabled = true;
  try {
    const status = await api("/api/router/test", { method: "POST", body: "{}" });
    $("mt-hint").textContent = status.connected
      ? `SSH ok · ${status.identity} ${status.version}`
      : status.last_error;
    await refresh();
  } catch (err) {
    $("mt-hint").textContent = err.message;
  } finally {
    $("btn-test").disabled = false;
  }
});

$("vendor-pick").addEventListener("focus", () => {
  if (lastOverview?.vendor) {
    lastVendorPick = lastOverview.vendor;
  } else {
    lastVendorPick = $("vendor-pick").value;
  }
});

$("vendor-pick").addEventListener("change", async (ev) => {
  const vendor = ev.target.value;
  const previous = lastVendorPick || lastOverview?.vendor || ev.target.value;
  if (!vendor || vendor === previous) return;

  ev.target.value = previous;
  const profile = getRouterProfile(vendor);
  if (!profile) {
    alert(
      `Cannot switch to ${vendor}: router profile unavailable.\n\n` +
        "Restart the collector after editing .env, then try again."
    );
    return;
  }

  if (!profile.configured) {
    alert(formatMissingVendorMessage(profile));
    return;
  }

  if (!confirm(vendorSwitchMessage(previous, vendor, profile))) {
    return;
  }

  ev.target.value = vendor;
  try {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({ blocker_vendor: vendor }),
    });
    lastVendorPick = vendor;
    await refresh();
  } catch (err) {
    alert(err.message);
    ev.target.value = previous;
    await refresh();
  }
});

$("btn-upgrade-check").addEventListener("click", async () => {
  $("btn-upgrade-check").disabled = true;
  try {
    const status = await api("/api/upgrade/status");
    $("upgrade-hint").textContent = status.message || (status.update_available ? "Update available" : "Up to date");
    if (status.git) {
      $("upgrade-line").textContent = `Version ${status.installed_version} · ${status.branch} @ ${status.commit}`;
    }
  } catch (err) {
    $("upgrade-hint").textContent = err.message;
  } finally {
    $("btn-upgrade-check").disabled = false;
  }
});

$("btn-upgrade").addEventListener("click", async () => {
  if (!confirm("Pull latest code, pip install, and restart if configured?")) return;
  $("btn-upgrade").disabled = true;
  try {
    const result = await api("/api/upgrade", {
      method: "POST",
      body: JSON.stringify({ restart: true }),
    });
    $("upgrade-hint").textContent = result.message || "Upgrade finished";
    if (result.previous_version && result.installed_version) {
      $("upgrade-line").textContent = `Version ${result.installed_version} (was ${result.previous_version})`;
    }
    if (result.restarted) {
      $("upgrade-hint").textContent += " — reloading…";
      setTimeout(() => window.location.reload(), 3000);
    } else {
      alert("Upgrade complete. Restart the collector process to load new code.");
    }
  } catch (err) {
    alert(err.message);
    $("upgrade-hint").textContent = err.message;
  } finally {
    $("btn-upgrade").disabled = false;
  }
});

refresh();
setInterval(refresh, 2000);

function initCollapsiblePanels() {
  for (const el of document.querySelectorAll("details.collapsible[data-panel]")) {
    const key = `collector-panel-${el.dataset.panel}`;
    const saved = localStorage.getItem(key);
    el.open = saved === "open";
    el.addEventListener("toggle", () => {
      localStorage.setItem(key, el.open ? "open" : "closed");
    });
  }
}

initCollapsiblePanels();
