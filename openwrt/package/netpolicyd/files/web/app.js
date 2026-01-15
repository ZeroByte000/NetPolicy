const sampleRuleset = `rules:
  - name: zoom_priority
    priority: 100
    when:
      state: NORMAL
    match:
      sni: "*.zoom.us"
      protocol: tcp
    action:
      route: tunnel_fast

  - name: fallback_if_high_latency
    priority: 80
    when:
      state: [DEGRADED, FAILOVER]
    match:
      latency_ms: ">120"
    action:
      switch_route: backup

  - name: block_suspicious_port
    priority: 60
    disable: FAILOVER
    match:
      port: "6667,1000-2000"
      protocol: tcp
    action:
      block: true

  - name: default_log
    priority: 10
    match:
      any: true
    action:
      route: direct
      log: true
`;

const rulesetEl = document.getElementById("ruleset");
const decisionEl = document.getElementById("decision");
const logsEl = document.getElementById("logs");
const rulesetFileEl = document.getElementById("ruleset-file");
const xrayUrlsEl = document.getElementById("xray-urls");
const xrayOutputEl = document.getElementById("xray-output");
const xrayGenBtn = document.getElementById("xray-gen");
const xrayStartBtn = document.getElementById("xray-start");
const xrayStopBtn = document.getElementById("xray-stop");
const xrayRestartBtn = document.getElementById("xray-restart");
const xrayStatusBtn = document.getElementById("xray-status");
const xrayStatusEl = document.getElementById("xray-status-output");
const xrayLogsBtn = document.getElementById("xray-refresh-logs");
const xrayLogsEl = document.getElementById("xray-logs");
const xrayUiHostEl = document.getElementById("xray-ui-host");
const xrayUiBaseEl = document.getElementById("xray-ui-base");
const openMetacubeBtn = document.getElementById("open-metacube");
const openYacdBtn = document.getElementById("open-yacd");
const xrayAutoRefreshEl = document.getElementById("xray-auto-refresh");
const vpnStartBtn = document.getElementById("vpn-start");
const vpnStopBtn = document.getElementById("vpn-stop");
const vpnStatusEl = document.getElementById("vpn-status");
const telemetryRefreshBtn = document.getElementById("telemetry-refresh");
const telemetryAutoEl = document.getElementById("telemetry-auto");
const telemetryOutputEl = document.getElementById("telemetry-output");
const menuToggle = document.getElementById("menu-toggle");
const menuClose = document.getElementById("menu-close");
const sidebar = document.getElementById("sidebar");
const sidebarBackdrop = document.getElementById("sidebar-backdrop");

const stateEl = document.getElementById("state");
const sniEl = document.getElementById("sni");
const protocolEl = document.getElementById("protocol");
const portEl = document.getElementById("port");
const latencyEl = document.getElementById("latency");
const rttEl = document.getElementById("rtt");

const runBtn = document.getElementById("run");
const loadBtn = document.getElementById("load-sample");
const logsBtn = document.getElementById("refresh-logs");

document.addEventListener("DOMContentLoaded", () => {
  if (rulesetEl && !rulesetEl.value) {
    rulesetEl.value = sampleRuleset;
  }
});

function parseNumber(value) {
  if (!value) return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

async function dryRun() {
  const payload = {
    ruleset: rulesetEl.value,
    state: stateEl.value,
    context: {
      sni: sniEl.value || null,
      protocol: protocolEl.value || null,
      port: parseNumber(portEl.value),
      latency_ms: parseNumber(latencyEl.value),
      rtt_ms: parseNumber(rttEl.value),
    },
  };

  decisionEl.textContent = "Running...";
  try {
    const res = await fetch("/api/dry-run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    if (!data.ok) {
      decisionEl.textContent = `Error: ${data.error || "unknown"}`;
      return;
    }

    const parts = [
      `state: ${data.state}`,
      `rule: ${data.rule || "<none>"}`,
      `action: ${data.action || "<none>"}`,
    ];
    decisionEl.textContent = parts.join("\n");
  } catch (err) {
    decisionEl.textContent = `Error: ${err}`;
  }
}

async function refreshLogs() {
  logsEl.textContent = "Loading...";
  try {
    const res = await fetch("/api/logs");
    const data = await res.json();
    if (!data.ok) {
      logsEl.textContent = data.error || "No logs";
      return;
    }
    logsEl.textContent = data.content || "No logs";
  } catch (err) {
    logsEl.textContent = `Error: ${err}`;
  }
}

if (runBtn) runBtn.addEventListener("click", dryRun);
if (loadBtn) loadBtn.addEventListener("click", () => {
  if (rulesetEl) rulesetEl.value = sampleRuleset;
});
if (logsBtn) logsBtn.addEventListener("click", refreshLogs);

if (rulesetFileEl) rulesetFileEl.addEventListener("change", (event) => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    if (rulesetEl) rulesetEl.value = String(reader.result || "");
  };
  reader.readAsText(file);
});

async function generateXray() {
  if (!xrayUrlsEl || !xrayOutputEl) return;
  const urlsText = xrayUrlsEl.value || "";
  xrayOutputEl.textContent = "Generating...";
  try {
    const res = await fetch("/api/xray-gen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls_text: urlsText }),
    });
    const data = await res.json();
    if (!data.ok) {
      xrayOutputEl.textContent = `Error: ${data.error || "unknown"}`;
      return;
    }
    const savedInfo = data.saved_to ? `\\n(saved: ${data.saved_to})` : "";
    xrayOutputEl.textContent = (data.config || "{}") + savedInfo;
  } catch (err) {
    xrayOutputEl.textContent = `Error: ${err}`;
  }
}

if (xrayGenBtn) xrayGenBtn.addEventListener("click", generateXray);

async function xrayAction(path) {
  if (!xrayStatusEl) return;
  xrayStatusEl.textContent = "Working...";
  try {
    const res = await fetch(path, { method: path.includes("/status") ? "GET" : "POST" });
    const data = await res.json();
    if (!data.ok) {
      xrayStatusEl.textContent = `Error: ${data.error || "unknown"}`;
      setXrayUiEnabled(false);
      return;
    }
    const pid = data.pid ? `pid=${data.pid}` : "pid=<none>";
    xrayStatusEl.textContent = `running=${data.running} ${pid}`;
    setXrayUiEnabled(Boolean(data.running));
  } catch (err) {
    xrayStatusEl.textContent = `Error: ${err}`;
    setXrayUiEnabled(false);
  }
}

async function refreshXrayLogs() {
  if (!xrayLogsEl) return;
  xrayLogsEl.textContent = "Loading...";
  try {
    const res = await fetch("/api/xray/logs");
    const data = await res.json();
    if (!data.ok) {
      xrayLogsEl.textContent = data.error || "No logs";
      return;
    }
    xrayLogsEl.textContent = data.content || "No logs";
  } catch (err) {
    xrayLogsEl.textContent = `Error: ${err}`;
  }
}

if (xrayStartBtn) xrayStartBtn.addEventListener("click", () => xrayAction("/api/xray/start"));
if (xrayStopBtn) xrayStopBtn.addEventListener("click", () => xrayAction("/api/xray/stop"));
if (xrayRestartBtn) xrayRestartBtn.addEventListener("click", () => xrayAction("/api/xray/restart"));
if (xrayStatusBtn) xrayStatusBtn.addEventListener("click", () => xrayAction("/api/xray/status"));
if (xrayLogsBtn) xrayLogsBtn.addEventListener("click", refreshXrayLogs);

function normalizeBasePath(value) {
  if (!value) return "";
  let base = value;
  while (base.endsWith("/")) {
    base = base.slice(0, -1);
  }
  return base.startsWith("/") ? base : `/${base}`;
}

function openXrayUi(path) {
  if (!xrayUiHostEl || !xrayUiBaseEl) return;
  const host = xrayUiHostEl.value || "127.0.0.1:9090";
  const base = normalizeBasePath(xrayUiBaseEl.value);
  const url = `http://${host}${base}${path}`;
  window.open(url, "_blank");
}

function setXrayUiEnabled(enabled) {
  if (openMetacubeBtn) openMetacubeBtn.disabled = false;
  if (openYacdBtn) openYacdBtn.disabled = false;
}

if (openMetacubeBtn) openMetacubeBtn.addEventListener("click", () => openXrayUi("/metacubexd"));
if (openYacdBtn) openYacdBtn.addEventListener("click", () => openXrayUi("/yacd"));

function updateVpnStatus() {
  if (!vpnStatusEl) return;
  if (!window.NetPolicyAndroid) {
    vpnStatusEl.textContent = "Not available";
    if (vpnStartBtn) vpnStartBtn.disabled = true;
    if (vpnStopBtn) vpnStopBtn.disabled = true;
    document.querySelectorAll(".android-only").forEach((el) => {
      el.style.display = "none";
    });
    return;
  }
  const status = window.NetPolicyAndroid.getVpnStatus();
  vpnStatusEl.textContent = status || "Unknown";
}

if (vpnStartBtn) vpnStartBtn.addEventListener("click", () => {
  if (window.NetPolicyAndroid) {
    window.NetPolicyAndroid.startVpn();
    setTimeout(updateVpnStatus, 500);
  }
});

if (vpnStopBtn) vpnStopBtn.addEventListener("click", () => {
  if (window.NetPolicyAndroid) {
    window.NetPolicyAndroid.stopVpn();
    setTimeout(updateVpnStatus, 500);
  }
});

updateVpnStatus();

async function refreshTelemetry() {
  if (!telemetryOutputEl) return;
  telemetryOutputEl.textContent = "Loading...";
  try {
    const res = await fetch("/api/telemetry");
    const data = await res.json();
    const lines = [
      `decisions: ${data.decisions ?? 0}`,
      `matches: ${data.matches ?? 0}`,
      `xray_start: ${data.xray_start ?? 0}`,
      `xray_stop: ${data.xray_stop ?? 0}`,
      `xray_restart: ${data.xray_restart ?? 0}`,
      `errors: ${data.errors ?? 0}`,
      `last_error: ${data.last_error || "-"}`,
    ];
    telemetryOutputEl.textContent = lines.join("\n");
  } catch (err) {
    telemetryOutputEl.textContent = `Error: ${err}`;
  }
}

if (telemetryRefreshBtn) telemetryRefreshBtn.addEventListener("click", refreshTelemetry);

function toggleSidebar(open) {
  if (open) {
    sidebar.classList.add("open");
    sidebarBackdrop.classList.add("open");
  } else {
    sidebar.classList.remove("open");
    sidebarBackdrop.classList.remove("open");
  }
}

if (menuToggle) menuToggle.addEventListener("click", () => toggleSidebar(true));
if (menuClose) menuClose.addEventListener("click", () => toggleSidebar(false));
if (sidebarBackdrop) sidebarBackdrop.addEventListener("click", () => toggleSidebar(false));
document.querySelectorAll(".sidebar a").forEach((link) => {
  link.addEventListener("click", () => toggleSidebar(false));
});

setXrayUiEnabled(true);

let autoRefreshTimer = null;
let telemetryTimer = null;

function setAutoRefresh(enabled) {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
  if (enabled) {
    autoRefreshTimer = setInterval(() => {
      xrayAction("/api/xray/status");
    }, 4000);
  }
}

if (xrayAutoRefreshEl) xrayAutoRefreshEl.addEventListener("change", () => {
  setAutoRefresh(xrayAutoRefreshEl.checked);
});

function setTelemetryAuto(enabled) {
  if (telemetryTimer) {
    clearInterval(telemetryTimer);
    telemetryTimer = null;
  }
  if (enabled) {
    telemetryTimer = setInterval(refreshTelemetry, 5000);
  }
}

if (telemetryAutoEl) telemetryAutoEl.addEventListener("change", () => {
  setTelemetryAuto(telemetryAutoEl.checked);
});

refreshTelemetry();
