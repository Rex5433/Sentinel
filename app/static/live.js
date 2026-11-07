"use strict";
const $ = (id) => document.getElementById(id);
const post = {method: "POST", headers: {"X-Sentinel-Import": "1"}};
const ui = {config: null, id: null, token: null, active: false, revision: -1, socket: null,
  sequence: 0, review: null, lastWatch: null, savedRevision: -1, saving: false, ownedConnection: null};
let pendingConnection = null;
let submittingPassword = false;
const labels = {
  critical: ["Critical review", "critical"], warning: ["Flagged for review", "flagged"],
  lead: ["Network lead", "lead"], context: ["Needs context", "context"]
};

function node(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = text;
  if (className) result.className = className;
  return result;
}

async function request(path, options) {
  const response = await fetch(path, {cache: "no-store", ...options});
  if (response.status === 401) window.location.replace("/login");
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch (_) {}
    const error = new Error(message);
    error.status = response.status;
    error.retryAfter = Number(response.headers.get("Retry-After")) || 0;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function original(event) {
  const details = node("details");
  const value = node("pre");
  details.append(node("summary", "Original log record"), value);
  details.addEventListener("toggle", () => {
    if (details.open && !value.textContent) value.textContent = JSON.stringify(event.raw_record, null, 2);
  });
  return details;
}

function record(title, severity) {
  const [label, style] = labels[severity] ?? [];
  const card = node("article", undefined, style ? `record review-${style}` : "record");
  const header = node("div", undefined, "event-heading");
  header.append(node("h4", title, "record-head"));
  if (label) header.append(node("span", label, `review-badge badge-${style}`));
  card.append(header);
  return card;
}

function eventText(event) {
  if (event.message) return event.message;
  const raw = event.raw_record;
  const data = raw?.EventData ?? raw;
  return [event.actor, event.source_ip, data?.NewProcessName, data?.CommandLine,
    data?.TargetUserName, data?.TaskName, data?.ServiceName].filter(Boolean).join(" · ") || "Open the original record for event fields.";
}

function renderReview(review) {
  ui.review = review;
  const coverage = $("live-source-coverage");
  coverage.hidden = ui.config?.platform !== "windows";
  if (!coverage.hidden) {
    const count = review.process_creation_events ?? 0;
    const commands = review.process_creation_with_command_line ?? 0;
    coverage.textContent = ui.config.channel !== "Security"
      ? "Watching Windows System. The encoded PowerShell test needs the Security channel. Console output is not streamed as an event log."
      : !count ? "No process-creation events (4688) in the retained buffer. Check Audit Process Creation on the source host; this buffer alone cannot confirm whether auditing is enabled."
      : !commands ? `${count} process-creation events received, but no command-line fields. Check “Include command line in process creation events” on the source host to review encoded launches.`
      : `${count} process-creation events; ${commands} with command lines. The printed test message is Base64-encoded in the command line: filter for EncodedCommand, not Sentinel live alert test.`;
  }
  const query = $("live-filter").value.trim().toLowerCase();
  const flaggedOnly = $("live-filter-flags").value === "flagged";
  const matches = event => !query || JSON.stringify(event).toLowerCase().includes(query);
  const evidence = new Map(review.events.map(event => [event.event_id, event]));
  const findings = $("live-findings");
  findings.replaceChildren();
  for (const entry of review.findings) {
    const finding = entry.finding;
    if (query && !(entry.title + " " + finding.explanation).toLowerCase().includes(query) &&
        !finding.evidence_event_ids.some(id => evidence.has(id) && matches(evidence.get(id)))) continue;
    if (flaggedOnly && entry.severity === "context") continue;
    const card = record(entry.title ?? "Authentication burst", entry.severity ?? "warning");
    card.append(node("p", finding.explanation), node("p", finding.timestamp_utc ?? "Unknown time", "small muted"));
    const details = node("details");
    details.append(node("summary", `Supporting records (${finding.evidence_event_ids.length})`));
    details.addEventListener("toggle", () => {
      if (!details.open || details.children.length > 1) return;
      for (const id of finding.evidence_event_ids) {
        const event = evidence.get(id);
        if (event) details.append(node("p", eventText(event)), original(event));
      }
    });
    card.append(details);
    findings.append(card);
  }
  if (!findings.children.length) findings.append(node("p", "No findings match the displayed filter.", "muted"));
  if (review.findings.length < review.finding_count) findings.append(node("p", `Showing the latest ${review.findings.length} of ${review.finding_count} findings.`, "small muted"));
  const events = $("live-events");
  events.replaceChildren();
  const matching = review.events.filter(event => matches(event) &&
    (!flaggedOnly || (review.flagged[event.event_id] && review.flagged[event.event_id] !== "context")));
  for (const event of matching.slice(-50).reverse()) {
    const source = event.windows_event_id ? `Windows event ${event.windows_event_id}` : event.service ?? "Journal";
    const card = record(`${event.host ?? "Unknown host"} · ${source}`, review.flagged[event.event_id]);
    card.append(node("p", event.timestamp_utc ?? "Unknown time", "small muted"),
      node("p", eventText(event)), original(event));
    events.append(card);
  }
  if (!matching.length) events.append(node("p", "No received events match the displayed filter.", "muted"));
  $("live-filter-status").textContent = `${matching.length} of ${review.events.length} retained events match. Showing up to 50 latest matches.`;
}

for (const id of ["live-filter", "live-filter-flags"]) $(id).addEventListener("input", () => {
  if (ui.review) renderReview(ui.review);
});

function renderWatch(data) {
  ui.lastWatch = data;
  ui.active = data.active;
  ui.revision = data.revision;
  if (typeof data.saved_revision === "number") ui.savedRevision = Math.max(ui.savedRevision, data.saved_revision);
  const reconnect = !data.active && ui.config?.authentication === "password";
  if (reconnect) ui.config.password_required = true;
  $("live-start").disabled = data.active || reconnect;
  $("live-stop").disabled = !data.active;
  $("live-save").disabled = ui.saving || !data.parsed || ui.savedRevision === data.revision;
  $("live-autosave").disabled = data.active;
  connectionControls(data.active);
  $("live-gap").hidden = !data.possible_gap;
  const checked = data.checked_at ? ` · Last completed pull ${new Date(data.checked_at).toLocaleTimeString()}` : "";
  $("live-coverage").textContent = `${data.retained} retained from the latest hour · ${data.age_evicted ?? data.evicted ?? 0} aged out · ${data.capacity_evicted ?? 0} removed by safety caps · ${data.skipped} without a usable identifier`;
  if (data.rejected) $("live-coverage").textContent += ` · ${data.rejected} rejected by the log parser`;
  $("live-status").textContent = [data.stopped, data.error].filter(Boolean).join(" ") ||
    (data.active ? "Watching for log records." : "");
  if (reconnect) $("live-status").textContent += " Select Connect to sign in again.";
  if (data.active) $("live-connect-status").textContent = "SSH connected. Receiving log records.";
  else if (reconnect) $("live-connect-status").textContent = "SSH password session closed. Select Connect to sign in again.";
  if (data.review) renderReview(data.review);
  $("live-archive-status").className = data.archive_error ? "small error" : "small";
  $("live-archive-status").textContent = data.archive_error
    ? `Automatic saving needs attention: ${data.archive_error}`
    : data.autosave ? `Automatic saving on · ${data.archive_saved ?? 0} chunks saved to Logs.` : "Automatic saving off. Use Save capture to Logs for a retained snapshot.";
  if ((data.archive_saved ?? 0) > 0) $("live-open-library").hidden = false;
  pollingStatus(!data.active ? "Stopped" : data.error ? "Retrying log read" : data.pulls ? "Watching — checking for new events" : "Starting watch",
    !data.active ? "stopped" : data.error ? "retrying" : "watching");
  const duration = data.duration_ms == null ? "" : ` · Last read ${(data.duration_ms / 1000).toFixed(1)}s`;
  $("live-poll-detail").textContent = `${data.pulls ?? 0} completed pulls / ${data.attempts ?? 0} attempts · ${data.new_last_pull ?? 0} new in last pull · ${data.received ?? 0} received this watch${checked}${duration}`;
  if (data.error || data.stopped) $("live-poll-detail").textContent += ` · ${[data.stopped, data.error].filter(Boolean).join(" ")}`;
}

function pollingStatus(text, kind) {
  $("live-poll-state").textContent = text;
  $("live-poll-state").parentElement.dataset.state = kind;
}

function closeStream() {
  const socket = ui.socket;
  ui.socket = null;
  if (socket) socket.close();
}

function watchPath(action) {
  return `/api/live/${ui.id}/${action}?token=${encodeURIComponent(ui.token ?? "")}`;
}

function streamDisconnected(message) {
  if (!ui.active) return;
  closeStream();
  ui.sequence++;
  if (ui.lastWatch) renderWatch({...ui.lastWatch, active: false, stopped: message});
  pollingStatus("Disconnected — reconnect to resume", "paused");
  $("live-status").textContent = message;
  $("live-poll-detail").textContent = "Live updates have stopped. Reconnect to start a new watch. Retained records can still be saved.";
  fetch(watchPath("stop"), {...post, keepalive: true}).catch(() => {});
}

function openStream() {
  const sequence = ui.sequence;
  const url = new URL(watchPath("stream"), window.location.href);
  url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(url);
  ui.socket = socket;
  pollingStatus("Opening live stream…", "checking");
  socket.addEventListener("message", event => {
    if (ui.socket !== socket || ui.sequence !== sequence) return;
    try {
      const data = JSON.parse(event.data);
      if (data.id !== ui.id || typeof data.active !== "boolean") throw new Error("Unexpected live stream response.");
      renderWatch(data);
      if (socket.readyState === WebSocket.OPEN) socket.send("ack");
      if (!data.active) closeStream();
    } catch (_) { streamDisconnected("The live stream returned an invalid response and was closed."); }
  });
  socket.addEventListener("error", () => {
    if (ui.socket === socket && ui.sequence === sequence) streamDisconnected("The live connection was interrupted. Its watch is closing.");
  });
  socket.addEventListener("close", () => {
    if (ui.socket === socket && ui.sequence === sequence) streamDisconnected("The live connection closed. Its watch has stopped.");
  });
}

$("live-start").addEventListener("click", async () => {
  connectionControls(true);
  $("live-start").disabled = true;
  $("live-save").disabled = true;
  $("live-open-library").hidden = true;
  try {
    const params = new URLSearchParams({host: ui.config.host, port: ui.config.port});
    const result = await request(`/api/live/start?${params}`, {...post,
      headers: {...post.headers, "Content-Type": "application/json"},
      body: JSON.stringify({autosave: $("live-autosave").checked})});
    ui.id = result.id;
    ui.token = result.token;
    ui.saving = false;
    ui.savedRevision = -1;
    ui.sequence++;
    renderWatch(result);
    openStream();
  } catch (error) {
    if (ui.active && ui.token) streamDisconnected(error.message);
    else {
      $("live-status").textContent = error.message;
      $("live-start").disabled = false;
      connectionControls(ui.active);
    }
  }
});

function connectionControls(disabled) {
  for (const control of $("live-connect-form").elements) control.disabled = disabled;
  $("live-channel").disabled = disabled || $("live-platform").value !== "windows";
}

function sourceControls() {
  const windows = $("live-platform").value === "windows";
  $("live-channel-label").hidden = !windows;
  $("live-channel").disabled = !windows;
}

$("live-platform").addEventListener("change", sourceControls);

function renderConfig(config) {
  ui.config = config;
  const source = config.platform === "windows" ? `Windows ${config.channel}` : "Linux journal";
  $("live-target").textContent = !config.enabled ? "Connect a Windows or Linux source below." :
    !config.ready ? config.detail : `${source} · ${config.host}:${config.port} · Checks about every ${config.poll_seconds} seconds · Rolling latest hour`;
  $("live-start").disabled = !config.ready || config.password_required || ui.active;
  if (config.ready) {
    $("live-ssh").value = `ssh ${config.username}@${config.host} -p ${config.port}`;
    $("live-identity").value = config.identity_file;
    $("live-platform").value = config.platform;
    $("live-channel").value = config.channel;
    $("live-authentication").value = config.authentication === "password" ? "password" : "auto";
    sourceControls();
  }
}

function connected(config) {
  ui.sequence++;
  closeStream();
  ui.id = null;
  ui.token = null;
  ui.revision = -1;
  ui.review = null;
  ui.lastWatch = null;
  ui.savedRevision = -1;
  ui.ownedConnection = config.connection_id ?? null;
  pollingStatus("Not watching", "stopped");
  $("live-poll-detail").textContent = "Start a watch to check for new events.";
  $("live-source-coverage").hidden = true;
  $("live-gap").hidden = true;
  $("live-open-library").hidden = true;
  $("live-status").textContent = "";
  $("live-coverage").textContent = "The live view keeps the latest hour of received records, subject to record and memory limits.";
  $("live-archive-status").textContent = "";
  $("live-filter-status").textContent = "";
  for (const id of ["live-findings", "live-events"]) $(id).replaceChildren(node("p", "Waiting for data.", "muted"));
  renderConfig(config);
  $("live-connect-status").textContent = "SSH connection verified. Select Start watch.";
}

$("live-connect-form").addEventListener("submit", async event => {
  event.preventDefault();
  const payload = {ssh_command: $("live-ssh").value, platform: $("live-platform").value,
    channel: $("live-channel").value, identity_file: $("live-identity").value, authentication: $("live-authentication").value};
  connectionControls(true);
  $("live-start").disabled = true;
  $("live-save").disabled = true;
  $("live-connect-status").textContent = "Checking SSH access…";
  try {
    const config = await request("/api/live/connect", {...post,
      headers: {...post.headers, "Content-Type": "application/json"}, body: JSON.stringify(payload)});
    if (config.password_required) {
      pendingConnection = payload;
      $("live-password-target").textContent = payload.ssh_command;
      $("live-password-status").textContent = config.detail;
      $("live-password").value = "";
      $("live-password-dialog").showModal();
      $("live-connect-status").textContent = "Waiting for SSH password.";
    } else connected(config);
  } catch (error) {
    $("live-connect-status").textContent = error.message;
    $("live-start").disabled = !ui.config?.ready || ui.config?.password_required;
    $("live-save").disabled = !ui.id || !ui.review?.events.length;
  } finally {
    connectionControls(ui.active);
  }
});

$("live-password-cancel").addEventListener("click", () => $("live-password-dialog").close());
$("live-password-dialog").addEventListener("cancel", event => { if (submittingPassword) event.preventDefault(); });
$("live-password-dialog").addEventListener("close", () => {
  const canceled = pendingConnection !== null;
  pendingConnection = null;
  $("live-password").value = "";
  if (canceled && !ui.active) {
    $("live-connect-status").textContent = "Password prompt closed. Select Connect to try again.";
    $("live-start").disabled = !ui.config?.ready || ui.config?.password_required;
  }
});
$("live-password-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (submittingPassword || !pendingConnection) return;
  const body = JSON.stringify({...pendingConnection, password: $("live-password").value});
  $("live-password").value = "";
  submittingPassword = true;
  for (const control of $("live-password-form").elements) control.disabled = true;
  $("live-password-status").textContent = "Signing in…";
  try {
    const config = await request("/api/live/password", {...post,
      headers: {...post.headers, "Content-Type": "application/json"}, body});
    connected(config);
    pendingConnection = null;
    $("live-password-dialog").close();
    $("live-start").click();
  } catch (error) {
    $("live-password-status").textContent = error.message;
  } finally {
    submittingPassword = false;
    for (const control of $("live-password-form").elements) control.disabled = false;
    if ($("live-password-dialog").open) $("live-password").focus();
  }
});

$("live-stop").addEventListener("click", async () => {
  $("live-stop").disabled = true;
  try {
    const result = await request(watchPath("stop"), post);
    ui.sequence++;
    closeStream();
    renderWatch(result);
  } catch (error) {
    $("live-status").textContent = error.message;
    $("live-stop").disabled = false;
    $("live-start").disabled = Boolean(ui.config?.password_required);
  }
});

$("live-save").addEventListener("click", async () => {
  ui.saving = true;
  const watchId = ui.id;
  const revision = ui.revision;
  $("live-save").disabled = true;
  try {
    const saved = await request(watchPath("save"), post);
    if (ui.id !== watchId) return;
    ui.savedRevision = saved.saved_revision ?? revision;
    $("live-status").textContent = ui.active
      ? "Saved and analyzed a capture in Logs. The live watch continues while this tab stays open."
      : "Saved and analyzed the retained capture in Logs.";
    $("live-open-library").hidden = false;
  } catch (error) {
    if (ui.id !== watchId) return;
    $("live-status").textContent = error.message;
    $("live-save").disabled = false;
  } finally {
    if (ui.id === watchId) {
      ui.saving = false;
      $("live-save").disabled = !ui.lastWatch?.parsed || ui.savedRevision === ui.revision;
    }
  }
});

function stopOnLeave() {
  $("live-password").value = "";
  pendingConnection = null;
  if (ui.active && ui.token) fetch(watchPath("stop"), {...post, keepalive: true}).catch(() => {});
  ui.sequence++;
  closeStream();
  if (ui.active && ui.lastWatch) renderWatch({...ui.lastWatch, active: false, stopped: "The Live logs page was left. Start a new watch to resume."});
  if (ui.ownedConnection) fetch(`/api/live/disconnect?connection_id=${encodeURIComponent(ui.ownedConnection)}`, {...post, keepalive: true}).catch(() => {});
  ui.ownedConnection = null;
}

window.addEventListener("pagehide", stopOnLeave);
$("live-logout").addEventListener("click", async () => {
  stopOnLeave();
  try { await request("/api/auth/logout", post); window.location.replace("/login"); }
  catch (error) { $("live-status").textContent = error.message; }
});

request("/api/auth/me").then(user => {
  $("live-user").textContent = `Signed in as ${user.username}`;
}).catch(() => {});
request("/api/live/status").then(renderConfig).catch(error => { $("live-target").textContent = error.message; });
