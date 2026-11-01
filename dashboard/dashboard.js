"use strict";
const $ = (id) => document.getElementById(id);
const filePreview = location.protocol === "file:";
if (filePreview) {
  $("loginForm").hidden = true;
  $("fileOpenNotice").hidden = false;
}
const state = {
  snapshot: null,
  csrf: null,
  socket: null,
  view: "overview",
  online: false,
  paused: false,
  selected: null,
  reconnect: null,
  lastMessage: 0,
  manualLock: false,
  policyDirty: false,
  policyRevision: null,
  policyReview: null,
  managementBusy: false,
};
const titles = {
  overview: [
    "Security overview",
    "Visibility into file activity and the evidence behind every alert.",
  ],
  incidents: [
    "Incident investigation",
    "Review the evidence. Understand the actor. Record the outcome.",
  ],
  activity: [
    "Activity stream",
    "A live view of file changes inside your protected directories.",
  ],
  protection: [
    "Protection & rules",
    "Your monitoring scope, collector health, and executable rules.",
  ],
  settings: [
    "Settings & control",
    "Manage collection, protected scope, detection thresholds, and operator response policy.",
  ],
};
const number = (value) => new Intl.NumberFormat().format(value || 0);
const time = (value) =>
  new Date(value * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
const icon = (name) => {
  const node = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "#i-" + name);
  node.append(use);
  return node;
};
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function badge(text, kind = "neutral") {
  return el("span", "badge " + kind, text);
}
function toast(message) {
  $("toast").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => ($("toast").hidden = true), 5500);
}
function setView(view) {
  if (!titles[view]) return;
  state.view = view;
  document
    .querySelectorAll(".view")
    .forEach((node) => (node.hidden = node.id !== view + "View"));
  document
    .querySelectorAll(".nav-item")
    .forEach((node) =>
      node.classList.toggle("active", node.dataset.view === view),
    );
  $("pageTitle").replaceChildren(
    document.createTextNode(titles[view][0]),
    el("span", "heading-dot", "."),
  );
  $("pageDescription").textContent = titles[view][1];
  $("breadcrumb").textContent =
    view === "overview"
      ? "Overview"
      : view === "incidents"
        ? "Incidents"
        : view === "activity"
          ? "Activity stream"
          : view === "settings"
            ? "Settings & control"
            : "Protection & rules";
  history.replaceState(null, "", "#" + view);
}
document
  .querySelectorAll("[data-view]")
  .forEach((button) =>
    button.addEventListener("click", () => setView(button.dataset.view)),
  );
function connection(online, label) {
  state.online = online;
  $("connectionLabel").textContent = label;
  $("connectionDot").className = "status-dot " + (online ? "" : "muted");
  $("offlineBanner").hidden = online;
  $("engineDot").className = "status-dot " + (online ? "" : "muted");
  if (!online) {
    $("engineState").textContent = "State unavailable";
    $("postureTitle").textContent = "Endpoint state unavailable";
    $("postureText").textContent =
      "Connection lost. Values below are from the last received snapshot.";
    $("postureBanner").classList.add("warning");
    $("postureBadge").textContent = "OFFLINE";
  }
  if (state.selected) renderDetails();
  renderManagement();
}
async function api(path, options = {}) {
  if (filePreview) {
    throw new Error(
      "Open the running console at http://127.0.0.1:8001/ to sign in.",
    );
  }
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(state.csrf ? { "X-CSRF-Token": state.csrf } : {}),
      ...options.headers,
    },
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The engine returned an invalid response");
  }
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/session") lock(false);
    throw new Error(data.error || "Request failed");
  }
  return data;
}
$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("loginError").textContent = "";
  const button = event.submitter;
  button.disabled = true;
  try {
    const result = await api("/api/session", {
      method: "POST",
      body: JSON.stringify({ token: $("accessKey").value }),
    });
    state.csrf = result.csrf;
    $("accessKey").value = "";
    state.manualLock = false;
    $("loginScreen").hidden = true;
    $("app").hidden = false;
    setView(location.hash.slice(1) || "overview");
    connect();
  } catch (error) {
    $("loginError").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
function connect() {
  if (state.manualLock) return;
  clearTimeout(state.reconnect);
  const socket = new WebSocket(
    (location.protocol === "https:" ? "wss://" : "ws://") +
      location.host +
      "/ws",
  );
  state.socket = socket;
  socket.onopen = () => connection(true, "Connected · awaiting state");
  socket.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }
    state.lastMessage = Date.now();
    if (msg.type === "snapshot") {
      state.snapshot = msg.data;
      render();
    } else if (msg.type === "incident" && state.snapshot) {
      const index = state.snapshot.incidents.findIndex(
        (item) => item.id === msg.data.id,
      );
      if (index >= 0) state.snapshot.incidents[index] = msg.data;
      else state.snapshot.incidents.unshift(msg.data);
      state.snapshot.incidents = state.snapshot.incidents.slice(0, 200);
      renderIncidents();
      if (state.selected === msg.data.id) renderDetails();
    } else if (msg.type === "activity" && state.snapshot) {
      state.snapshot.activity.unshift(msg.data);
      state.snapshot.activity = state.snapshot.activity.slice(0, 200);
      if (!state.paused && state.view === "activity") renderActivity();
    }
  };
  socket.onclose = () => {
    connection(false, "Disconnected");
    if (!state.manualLock)
      state.reconnect = setTimeout(async () => {
        try {
          state.snapshot = await api("/api/snapshot");
          connect();
        } catch (error) {
          if (!$("app").hidden) state.reconnect = setTimeout(connect, 5000);
        }
      }, 2500);
  };
  socket.onerror = () => connection(false, "Connection error");
}
async function lock(revoke = true) {
  state.manualLock = true;
  clearTimeout(state.reconnect);
  if (revoke && state.csrf) {
    try {
      await api("/api/session", { method: "DELETE" });
    } catch {}
  }
  state.csrf = null;
  if (state.socket) state.socket.close();
  state.snapshot = null;
  state.selected = null;
  $("incidentDialog").close();
  $("policyReviewDialog").close();
  $("monitoringDialog").close();
  state.policyDirty = false;
  state.policyRevision = null;
  state.policyReview = null;
  $("app").hidden = true;
  $("loginScreen").hidden = false;
  $("loginError").textContent = "";
  $("accessKey").focus();
}
$("logoutButton").addEventListener("click", () => lock());
setInterval(() => {
  if (state.socket?.readyState === WebSocket.OPEN) {
    state.socket.send("ping");
    if (state.lastMessage && Date.now() - state.lastMessage > 15000)
      connection(false, "Telemetry stale");
  }
}, 5000);
function render() {
  const s = state.snapshot;
  if (!s) return;
  connection(true, "Live connection");
  $("demoBadge").hidden = !s.demo;
  $("workspaceType").textContent = s.demo
    ? "Demonstration workspace"
    : "This device";
  $("engineState").textContent =
    s.health === "running"
      ? "Monitoring active"
      : s.health === "degraded"
        ? "Monitoring degraded"
        : s.health === "paused"
          ? "Monitoring paused"
          : s.demo
            ? "Demo workspace"
            : s.health;
  $("engineMode").textContent = s.mode.replaceAll("_", " ") + " · local engine";
  $("engineDot").className =
    "status-dot " +
    (["degraded", "paused", "updating"].includes(s.health) ? "warning" : "");
  $("scannedCount").textContent = number(s.stats.scanned);
  $("incidentCount").textContent = number(s.stats.open_incidents);
  $("blockedCount").textContent = number(s.stats.blocked);
  const healthy = s.canaries.filter((item) => item.status === "healthy").length;
  $("canaryCount").textContent = healthy + " / " + s.canaries.length;
  $("canaryHint").textContent = s.demo
    ? "No live canaries in demonstration mode"
    : s.management?.monitoring_status !== "running"
      ? "Last known integrity state; monitoring is not active"
      : s.canaries.length - healthy
        ? "Integrity changes require review"
        : "Owned canaries verified";
  const latest = s.series.at(-1)?.rate || 0;
  $("eventRate").textContent = latest.toFixed(1) + " events / second";
  $("incidentHint").textContent = s.stats.open_incidents
    ? "Review the evidence in the queue"
    : "No open incidents";
  $("navIncidentCount").textContent = number(s.stats.open_incidents);
  $("rootCount").textContent =
    s.demo || s.management?.monitoring_status !== "running"
      ? "0"
      : number(s.directories.length);
  $("coverageArc").style.strokeDashoffset =
    s.demo || s.management?.monitoring_status !== "running"
      ? "308"
      : s.health === "running"
        ? "0"
        : "100";
  $("policyLabel").textContent = s.mode.replaceAll("_", " ");
  $("lastUpdated").textContent = "Updated " + time(s.timestamp);
  const warning = s.health !== "running" || s.stats.open_incidents > 0;
  $("postureBanner").classList.toggle("warning", warning);
  $("postureTitle").textContent = s.demo
    ? "Demonstration workspace — no live endpoint actions"
    : s.health === "paused"
      ? "Monitoring is paused — console controls remain available"
      : s.health === "updating"
        ? "Updating collection policy"
        : s.health === "degraded"
          ? "Monitoring needs attention"
          : s.stats.open_incidents
            ? "Monitoring active · incidents need review"
            : "File monitoring is active";
  $("postureText").textContent = s.demo
    ? "Sample incident records are isolated from your files and processes."
    : s.management?.last_error
      ? s.management.last_error
      : s.health === "paused"
        ? s.management?.pause_until
          ? "Collection will resume at " +
            new Date(s.management.pause_until * 1000).toLocaleString() +
            ". Review or resume from Settings & control."
          : "No new file changes are being collected. Resume from Settings & control."
        : s.issues.length
          ? s.issues.join(" · ")
          : "Writer attribution is unavailable. Automatic termination is disabled; " +
            s.mode.replaceAll("_", " ") +
            " policy applies to operator requests.";
  $("postureBadge").textContent = s.demo
    ? "DEMO"
    : warning
      ? "REVIEW REQUIRED"
      : "MONITORING";
  renderChart(s.series);
  $("activityModeLabel").textContent = s.demo
    ? "Demonstration event history"
    : s.management?.monitoring_status === "running"
      ? "Live file activity"
      : "Collection paused · retained activity";
  renderIncidents();
  if (!state.paused) renderActivity();
  renderProtection();
  renderManagement();
  if (state.selected) renderDetails();
}
function renderChart(series) {
  const values = series.map((item) => item.rate);
  const max = Math.max(10, ...values);
  $("chartMax").textContent = number(Math.ceil(max));
  $("chartMid").textContent = number(Math.ceil(max / 2));
  const padded = Array(Math.max(0, 60 - values.length))
    .fill(0)
    .concat(values)
    .slice(-60);
  const points = padded.map((value, index) => [
    (index / 59) * 700,
    160 - (value / max) * 145,
  ]);
  const line = points
    .map(
      (point, index) =>
        (index ? "L" : "M") + point.map((value) => value.toFixed(2)).join(","),
    )
    .join(" ");
  $("chartLine").setAttribute("d", line);
  $("chartArea").setAttribute("d", line + " L700,170 L0,170 Z");
}
function incidentRow(item) {
  const row = el("tr");
  let cell = el("td");
  cell.append(badge(item.severity.toUpperCase(), item.severity));
  row.append(cell);
  cell = el("td");
  cell.append(
    el("span", "detection-title", item.reason),
    el("span", "detection-path", item.path),
  );
  cell.title = item.path;
  row.append(cell);
  row.append(el("td", "actor", item.process?.name || "Unresolved actor"));
  cell = el("td");
  cell.append(
    el(
      "span",
      "outcome",
      item.status === "resolved"
        ? "Acknowledged"
        : item.action.status.replaceAll("_", " "),
    ),
  );
  row.append(cell);
  row.append(el("td", "", time(item.timestamp)));
  cell = el("td");
  const button = el("button", "row-open");
  button.setAttribute("aria-label", "Inspect incident " + item.id);
  button.append(icon("arrow"));
  button.addEventListener("click", () => openDetails(item.id));
  cell.append(button);
  row.append(cell);
  return row;
}
function renderIncidents() {
  if (!state.snapshot) return;
  const items = state.snapshot.incidents;
  const query = $("incidentSearch").value.toLowerCase();
  const filter = $("incidentFilter").value;
  const filtered = items.filter(
    (item) =>
      (filter === "all" ||
        item.status === filter ||
        item.severity === filter) &&
      [item.reason, item.path, item.process?.name || ""]
        .join(" ")
        .toLowerCase()
        .includes(query),
  );
  $("overviewIncidentRows").replaceChildren(
    ...items.slice(0, 4).map(incidentRow),
  );
  $("incidentRows").replaceChildren(...filtered.map(incidentRow));
  $("overviewEmpty").hidden = items.length > 0;
  $("incidentEmpty").hidden = filtered.length > 0;
  $("overviewIncidentCount").textContent = number(items.length);
  $("incidentResultCount").textContent =
    filtered.length + " of " + items.length + " retained records";
}
$("incidentSearch").addEventListener("input", renderIncidents);
$("incidentFilter").addEventListener("change", renderIncidents);
function renderActivity() {
  const items = state.snapshot?.activity || [];
  $("activityList").replaceChildren(
    ...items.map((item) => {
      const row = el("div", "activity-item");
      row.append(
        el("time", "", time(item.timestamp)),
        badge(item.type.toUpperCase(), item.is_canary ? "critical" : "neutral"),
      );
      const path = el("span", "activity-path", item.dest_path || item.src_path);
      path.title = item.src_path;
      row.append(
        path,
        el(
          "span",
          "activity-analysis",
          item.entropy === null || item.entropy === undefined
            ? item.analysis_status || "unknown"
            : item.entropy.toFixed(2) + " bits / byte",
        ),
      );
      return row;
    }),
  );
  $("activityEmpty").hidden = items.length > 0;
}
$("pauseButton").addEventListener("click", () => {
  state.paused = !state.paused;
  $("pauseButton").textContent = state.paused ? "Resume view" : "Pause view";
  if (!state.paused) renderActivity();
});
function renderProtection() {
  const s = state.snapshot;
  $("directoryList").replaceChildren(
    ...s.directories.map((path) => {
      const node = el("div", "directory");
      node.append(icon("folder"));
      const content = el("div");
      const canaries = s.canaries.filter((item) =>
        item.path.toLowerCase().startsWith(path.toLowerCase()),
      );
      content.append(
        el("strong", "", path),
        el(
          "small",
          "",
          s.demo
            ? "Demonstration configuration"
            : canaries.filter((item) => item.status === "healthy").length +
                " / " +
                canaries.length +
                " owned canaries healthy",
        ),
      );
      node.append(
        content,
        badge(
          s.demo
            ? "NOT WATCHED"
            : s.runtime.file_monitor === "running"
              ? "WATCHED"
              : "UNAVAILABLE",
          s.runtime.file_monitor === "running" ? "blue" : "neutral",
        ),
      );
      return node;
    }),
  );
  const health = [
    ["File collector", s.runtime.file_monitor],
    ["Process context", s.runtime.process_monitor],
    [
      "Queue utilization",
      s.runtime.queue_depth + " / " + s.runtime.queue_capacity,
    ],
    ["Last queue age", s.runtime.queue_age_ms + " ms"],
    ["Lost events", number(s.stats.dropped)],
    ["Analysis errors", number(s.stats.analysis_errors)],
    ["Analysis skipped", number(s.stats.analysis_skipped)],
    ["UI messages dropped", number(s.runtime.ui_dropped)],
    ["Automatic response", "Unavailable — no qualified attribution"],
  ];
  $("healthList").replaceChildren(
    ...health.map(([key, value]) => {
      const row = el("div");
      row.append(el("dt", "", key), el("dd", "", value));
      return row;
    }),
  );
  $("ruleList").replaceChildren(
    ...s.rules.map((rule) => {
      const row = el("div", "rule-item");
      const details = el("div");
      details.append(
        el("strong", "", rule.executable),
        el("p", "", rule.reason),
        el("p", "", rule.sha256),
      );
      const button = el("button", "button", "Remove rule");
      button.addEventListener("click", () =>
        command("remove_rule", { rule_id: rule.id }, button),
      );
      row.append(details, button);
      return row;
    }),
  );
  $("ruleEmpty").hidden = s.rules.length > 0;
  $("processRows").replaceChildren(
    ...s.processes.map((process) => {
      const row = el("tr");
      for (const value of [
        process.name,
        process.pid,
        process.writes_per_second,
        number(process.bytes_per_second),
      ])
        row.append(el("td", "", value));
      return row;
    }),
  );
  $("processEmpty").hidden = s.processes.length > 0;
}
function detailLine(label, value) {
  const row = el("div", "detail-line");
  row.append(el("span", "", label), el("strong", "", String(value)));
  return row;
}
function openDetails(id) {
  state.selected = id;
  renderDetails();
  $("incidentDialog").showModal();
}
function renderDetails() {
  const item = state.snapshot?.incidents.find(
    (entry) => entry.id === state.selected,
  );
  if (!item) return;
  const signature = JSON.stringify([
    item,
    state.online,
    state.snapshot.mode,
    state.snapshot.demo,
  ]);
  if (state.detailSignature === signature && $("incidentDialog").open) return;
  state.detailSignature = signature;
  $("detailTitle").textContent = item.reason;
  $("detailBody").replaceChildren(
    badge(item.severity.toUpperCase(), item.severity),
    detailLine("Observed", new Date(item.timestamp * 1000).toLocaleString()),
    detailLine("Path", item.path),
    detailLine(
      "Actor",
      item.process
        ? item.process.name + " · PID " + item.process.pid
        : "Unresolved — no writer identity",
    ),
    detailLine("Attribution", item.attribution),
    detailLine("Outcome", item.action.status.replaceAll("_", " ")),
    detailLine("Reason", item.action.reason),
    detailLine("Incident ID", item.id),
    el(
      "p",
      "detail-message",
      "Acknowledgment records your review; it does not mean the activity was remediated. Termination requires a captured process instance, terminate mode, and an authenticated operator request.",
    ),
  );
  $("terminateButton").disabled =
    !state.online ||
    !item.process ||
    state.snapshot.demo ||
    state.snapshot.mode !== "terminate";
  $("resolveButton").disabled = !state.online || item.status === "resolved";
  $("terminateButton").title = item.process
    ? "Revalidate process instance before response"
    : "Actor identity is unavailable";
  if (!state.snapshot.demo) {
    const review = el("div", "actor-review");
    const label = el("label", "", "Select a process for operator review");
    label.htmlFor = "actorSelector";
    const select = el("select");
    select.id = "actorSelector";
    select.append(el("option", "", "Choose a recent process instance"));
    for (const process of state.snapshot.processes) {
      const option = el("option", "", process.name + " · PID " + process.pid);
      option.value = process.pid + ":" + process.create_time.toFixed(6);
      select.append(option);
    }
    if (state.actorChoice) select.value = state.actorChoice;
    select.addEventListener("change", () => {
      state.actorChoice = select.value;
    });
    const choose = el("button", "button", "Select captured process");
    choose.disabled = !state.online;
    choose.addEventListener("click", () => {
      if (!select.value.includes(":"))
        return toast("Choose a process instance first.");
      command(
        "select_actor",
        { incident_id: item.id, process_key: select.value },
        choose,
      );
    });
    review.append(label, select, choose);
    if (item.process) {
      const allow = el("button", "button", "Record reviewed executable");
      allow.disabled = !state.online;
      allow.addEventListener("click", () => {
        const reason = prompt(
          "Reason for this executable review rule (canary incidents remain visible):",
        );
        if (reason?.trim())
          command(
            "allow",
            { incident_id: item.id, reason: reason.trim() },
            allow,
          );
      });
      review.append(allow);
    }
    $("detailBody").append(review);
  }
}
$("closeDialog").addEventListener("click", () => {
  $("incidentDialog").close();
  state.selected = null;
});
$("incidentDialog").addEventListener("close", () => {
  state.selected = null;
  state.actorChoice = null;
});
$("incidentDialog").addEventListener("click", (event) => {
  if (event.target === $("incidentDialog")) {
    $("incidentDialog").close();
    state.selected = null;
  }
});
$("resolveButton").addEventListener("click", () =>
  command("resolve", { incident_id: state.selected }, $("resolveButton")),
);
$("terminateButton").addEventListener("click", () => {
  if (
    confirm(
      "Terminate the captured process instance? Unsaved work may be lost.",
    )
  )
    command("terminate", { incident_id: state.selected }, $("terminateButton"));
});
async function command(name, fields, button) {
  if (!state.online) {
    toast("Reconnect to the engine before sending a command.");
    return;
  }
  button.disabled = true;
  try {
    const result = await api("/api/commands", {
      method: "POST",
      body: JSON.stringify({
        request_id: crypto.randomUUID(),
        command: name,
        ...fields,
      }),
    });
    toast(result.reason || result.status);
    state.snapshot = await api("/api/snapshot");
    render();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    if (state.selected) renderDetails();
  }
}
$("exportButton").addEventListener("click", () => {
  if (state.online) location.assign("/api/export");
  else toast("Reconnect before exporting current incident records.");
});

function fillPolicy(policy) {
  document.querySelectorAll("[data-policy]").forEach((input) => {
    const [section, key] = input.dataset.policy.split(".");
    const value = policy[section][key];
    if (input.type === "checkbox") input.checked = value;
    else input.value = Array.isArray(value) ? value.join("\n") : value;
  });
  $("policyReason").value = "";
}
function readPolicy() {
  const patch = {};
  document.querySelectorAll("[data-policy]").forEach((input) => {
    const [section, key] = input.dataset.policy.split(".");
    patch[section] ??= {};
    patch[section][key] =
      input.type === "checkbox"
        ? input.checked
        : input.type === "number"
          ? Number(input.value)
          : input.tagName === "TEXTAREA"
            ? input.value
                .split(/\r?\n/)
                .map((value) => value.trim())
                .filter(Boolean)
            : input.value;
  });
  return patch;
}
function renderManagement() {
  const management = state.snapshot?.management;
  const ready =
    state.online &&
    management &&
    management.commands_available !== false &&
    !state.managementBusy;
  const transitional = ["starting", "stopping"].includes(
    management?.monitoring_status,
  );
  $("monitorToggle").disabled = !ready || transitional;
  $("monitorRestart").disabled =
    !ready || management?.monitoring_status !== "running";
  $("reloadPolicy").disabled = !ready;
  $("previewPolicy").disabled = !ready || transitional;
  if (!management) {
    $("controlDescription").textContent = state.snapshot
      ? "This engine needs a restart to load management controls."
      : "Waiting for a current engine snapshot.";
    return;
  }
  const status = management.monitoring_status;
  $("controlStatus").textContent =
    (state.snapshot.demo ? "DEMO · " : "") + status.toUpperCase();
  $("controlStatus").className =
    "badge " + (status === "running" ? "blue" : "high");
  $("monitorToggle").textContent =
    status === "running"
      ? "Pause monitoring"
      : status === "faulted"
        ? "Retry monitoring"
        : "Start monitoring";
  $("controlDescription").textContent = state.snapshot.demo
    ? "These controls update an isolated demo policy. They do not watch your files or enable live process actions."
    : status === "running"
      ? "File collection is running. Pause or restart collectors here while keeping incident review and this console available."
      : status === "paused"
        ? (management.pause_until
            ? "Collection is paused until " +
              new Date(management.pause_until * 1000).toLocaleString() +
              "."
            : "Collection is paused until you resume it.") +
          " File changes during this interval are not collected."
        : status === "faulted"
          ? "Collection is unavailable. Review the error, correct the policy below, then retry monitoring."
          : "Collector transition in progress. Wait for the engine result.";
  $("policyRevision").textContent = "Saved revision " + management.revision;
  $("controlError").hidden = !management.last_error;
  $("controlError").textContent = management.last_error || "";
  if (!state.policyDirty && state.policyRevision !== management.revision) {
    fillPolicy(management.policy);
    state.policyRevision = management.revision;
  }
  const conflict =
    state.policyDirty && state.policyRevision !== management.revision;
  $("policyConflict").hidden = !conflict;
  $("previewPolicy").disabled ||= conflict;
  $("unsavedPolicy").textContent = state.policyDirty
    ? "Unsaved edits · review before applying"
    : "No unsaved edits";
  const history = state.snapshot.audit || [];
  const signature = history.map((item) => item.id).join(",");
  if (signature !== state.auditSignature) {
    state.auditSignature = signature;
    const rows = history
      .filter((item) => item.status !== "pending")
      .slice(0, 20);
    $("operatorHistory").replaceChildren(
      ...rows.map((item) => {
        const row = el("article", "operator-entry");
        row.append(
          el(
            "strong",
            "",
            item.command === "coverage_gap"
              ? "Collection coverage gap"
              : item.command?.replaceAll("_", " ") || "Operator action",
          ),
        );
        row.append(
          el(
            "p",
            "",
            item.reason ||
              item.result?.reason ||
              item.result?.status ||
              item.status ||
              "Recorded",
          ),
        );
        if (item.command === "coverage_gap")
          row.append(
            el(
              "p",
              "",
              "Transition duration: " + item.duration_seconds + " seconds",
            ),
          );
        row.append(
          el("time", "", new Date(item.timestamp * 1000).toLocaleString()),
        );
        return row;
      }),
    );
    if (!rows.length)
      $("operatorHistory").append(
        el("p", "empty small", "No operator changes recorded yet."),
      );
  }
}
$("policyForm").addEventListener("input", () => {
  state.policyDirty = true;
  $("policyMessage").textContent = "";
  renderManagement();
});
$("reloadPolicy").addEventListener("click", async () => {
  if (
    state.policyDirty &&
    !confirm("Discard your unsaved policy edits and reload the saved revision?")
  )
    return;
  try {
    state.snapshot = await api("/api/snapshot");
    state.policyDirty = false;
    state.policyRevision = null;
    $("policyMessage").textContent = "";
    render();
  } catch (error) {
    toast(error.message);
  }
});
async function managementRequest(name, fields) {
  if (!state.online)
    throw new Error("Reconnect before sending management commands.");
  state.managementBusy = true;
  renderManagement();
  try {
    return await api("/api/commands", {
      method: "POST",
      body: JSON.stringify({
        request_id: crypto.randomUUID(),
        command: name,
        ...fields,
      }),
    });
  } finally {
    state.managementBusy = false;
    renderManagement();
  }
}
$("policyForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("policyMessage").textContent = "";
  try {
    const patch = readPolicy();
    const reason = $("policyReason").value.trim();
    const result = await managementRequest("policy_preview", {
      expected_revision: state.policyRevision,
      patch,
      reason,
    });
    if (result.status !== "preview") throw new Error(result.reason);
    state.policyReview = { patch, reason, ...result };
    $("reviewRevision").textContent =
      "Reviewing saved revision " + result.revision + ". Reason: " + reason;
    $("policyChanges").replaceChildren(
      ...result.changes.map((change) => {
        const row = el("div", "policy-change");
        const format = (value) =>
          Array.isArray(value) ? value.join(" · ") : String(value);
        row.append(
          el("strong", "", change.setting),
          el("span", "", "Current: " + format(change.before)),
          el("span", "change-after", "Proposed: " + format(change.after)),
        );
        return row;
      }),
    );
    $("policyWarnings").replaceChildren(
      ...result.warnings.map((message) => el("li", "", message)),
    );
    $("policyGapAck").checked = false;
    $("terminationConfirmation").hidden =
      !result.requires_termination_confirmation;
    $("terminationPhrase").value = "";
    $("terminationPhrase").required = result.requires_termination_confirmation;
    $("reviewError").textContent = "";
    $("policyReviewDialog").showModal();
  } catch (error) {
    $("policyMessage").textContent = error.message;
  }
});
$("policyReviewForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const review = state.policyReview;
  if (!review) return;
  if (
    review.requires_termination_confirmation &&
    $("terminationPhrase").value !== "ENABLE MANUAL TERMINATION"
  ) {
    $("reviewError").textContent =
      "Type ENABLE MANUAL TERMINATION exactly to confirm the response mode.";
    return;
  }
  $("applyPolicy").disabled = true;
  try {
    const result = await managementRequest("policy_apply", {
      expected_revision: review.revision,
      patch: review.patch,
      reason: review.reason,
      preview_id: review.preview_id,
      acknowledge_gap: $("policyGapAck").checked,
      confirmation: $("terminationPhrase").value,
    });
    if (result.status !== "applied") throw new Error(result.reason);
    state.policyDirty = false;
    state.policyRevision = null;
    state.policyReview = null;
    $("policyReviewDialog").close();
    state.snapshot = await api("/api/snapshot");
    render();
    toast(result.reason);
  } catch (error) {
    $("reviewError").textContent = error.message;
  } finally {
    $("applyPolicy").disabled = false;
  }
});
function openMonitoring(operation) {
  state.monitoringOperation = operation;
  state.monitoringRevision = state.snapshot.management.revision;
  const pause = operation === "monitoring_pause",
    restart = operation === "monitoring_restart";
  $("monitoringTitle").textContent = pause
    ? "Pause monitoring"
    : restart
      ? "Restart collectors"
      : "Start monitoring";
  $("monitoringExplanation").textContent = pause
    ? "New file changes will not be collected while paused. Existing incidents and the console remain available."
    : restart
      ? "Collectors will stop and restart using the saved policy. The transition creates a recorded coverage gap."
      : "Start collectors using the saved protection policy. The engine will verify directories and canaries before reporting monitoring active.";
  $("pauseDurationField").hidden = !pause;
  $("monitoringGapField").hidden = !(pause || restart);
  $("monitoringGapAck").checked = false;
  $("monitoringGapAck").required = pause || restart;
  $("monitoringReason").value = "";
  $("monitoringError").textContent = "";
  $("applyMonitoring").textContent = pause
    ? "Pause monitoring"
    : restart
      ? "Restart collectors"
      : "Start monitoring";
  $("monitoringDialog").showModal();
}
$("monitorToggle").addEventListener("click", () =>
  openMonitoring(
    state.snapshot.management.monitoring_status === "running"
      ? "monitoring_pause"
      : "monitoring_resume",
  ),
);
$("monitorRestart").addEventListener("click", () =>
  openMonitoring("monitoring_restart"),
);
$("monitoringForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const operation = state.monitoringOperation;
  const fields = {
    expected_revision: state.monitoringRevision,
    reason: $("monitoringReason").value.trim(),
  };
  if (operation !== "monitoring_resume")
    fields.acknowledge_gap = $("monitoringGapAck").checked;
  if (operation === "monitoring_pause")
    fields.duration_seconds = Number($("pauseDuration").value);
  $("applyMonitoring").disabled = true;
  try {
    const result = await managementRequest(operation, fields);
    if (result.status !== "applied") throw new Error(result.reason);
    $("monitoringDialog").close();
    state.snapshot = await api("/api/snapshot");
    render();
    toast(result.reason);
  } catch (error) {
    $("monitoringError").textContent = error.message;
  } finally {
    $("applyMonitoring").disabled = false;
  }
});
document
  .querySelectorAll("[data-close]")
  .forEach((button) =>
    button.addEventListener("click", () => $(button.dataset.close).close()),
  );
