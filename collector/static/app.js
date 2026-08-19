const $ = (id) => document.getElementById(id);

const PROTOS = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6" };

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
  return `${d.unique_ports || row.score} ports / ${d.unique_hosts || "?"} hosts`;
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

function renderOverview(data) {
  const s = data.stats;
  const mt = data.mikrotik;
  $("m-rate").textContent = fmt(s.flows_per_sec);
  $("m-flows").textContent = fmt(s.flows);
  $("m-scans").textContent = fmt(data.detections.length);
  $("m-blocks").textContent = fmt(data.blocks.length);

  const probe = $("probe-pill");
  probe.textContent = s.last_flow_at
    ? `probe live · ${s.flows_per_sec}/s`
    : "probe waiting for NetFlow";
  probe.className = "pill" + (s.last_flow_at ? " ok" : "");

  const mtPill = $("mt-pill");
  mtPill.textContent = mt.connected
    ? `mikrotik ${mt.identity || mt.host} · ${mt.list_count} listed`
    : `mikrotik down · ${mt.host}:${mt.port}`;
  mtPill.className = "pill" + (mt.connected ? " ok" : " bad");
  $("mt-hint").textContent = mt.last_error || (mt.filter_ready ? "drop rules present" : "");
  $("list-name").textContent = mt.address_list || "blocked-scanners";

  $("auto-block").checked = !!data.auto_block;
  $("s-window").value = data.thresholds.scan_window_sec;
  $("s-vertical").value = data.thresholds.vertical_port_threshold;
  $("s-horizontal").value = data.thresholds.horizontal_host_threshold;
  $("s-spray").value = data.thresholds.unique_port_threshold;
  $("s-allow").value = data.thresholds.allowlist;

  const detBody = $("detections");
  detBody.innerHTML = "";
  if (!data.detections.length) {
    detBody.innerHTML = `<tr><td colspan="5" class="empty">No scanners in the last hour.</td></tr>`;
  } else {
    for (const row of data.detections) {
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

  const blockBody = $("blocks");
  blockBody.innerHTML = "";
  if (!data.blocks.length) {
    blockBody.innerHTML = `<tr><td colspan="5" class="empty">Nothing on the address-list yet.</td></tr>`;
  } else {
    for (const row of data.blocks) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${row.ip}</td>
        <td>${row.source}</td>
        <td>${row.reason}</td>
        <td>${age(row.created_at, data.now)}</td>
        <td><button type="button" class="ghost" data-unblock="${row.ip}">Unblock</button></td>`;
      blockBody.appendChild(tr);
    }
  }

  const flowBody = $("flows");
  flowBody.innerHTML = "";
  if (!data.flows.length) {
    flowBody.innerHTML = `<tr><td colspan="4" class="empty">Waiting for exported flows.</td></tr>`;
  } else {
    for (const row of data.flows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${row.src_ip}:${row.src_port}</td>
        <td>${row.dst_ip}:${row.dst_port}</td>
        <td>${PROTOS[row.proto] || row.proto}</td>
        <td>${fmt(row.bytes)}</td>`;
      flowBody.appendChild(tr);
    }
  }

  const log = $("events");
  log.innerHTML = data.events
    .map(
      (e) =>
        `<li class="${e.level}">${new Date(e.ts * 1000).toLocaleTimeString()}  ${e.message}</li>`
    )
    .join("");
}

async function refresh() {
  try {
    renderOverview(await api("/api/overview"));
  } catch (err) {
    if (err.message !== "auth") $("mt-hint").textContent = err.message;
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
  $("settings-panel").classList.toggle("hidden");
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
        allowlist: $("s-allow").value,
      }),
    });
    $("settings-panel").classList.add("hidden");
    await refresh();
  } catch (err) {
    alert(err.message);
  }
});

$("btn-test").addEventListener("click", async () => {
  $("btn-test").disabled = true;
  try {
    const status = await api("/api/mikrotik/test", { method: "POST", body: "{}" });
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

refresh();
setInterval(refresh, 2000);
