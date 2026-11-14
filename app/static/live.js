"use strict";
const $ = (id) => document.getElementById(id);
const post = {method: "POST", headers: {"X-Sentinel-Import": "1"}};
const ui = {config: null, id: null, token: null, active: false, revision: -1, timer: null, starting: false,
  sequence: 0, review: null, lastWatch: null, savedRevision: -1, saving: false, ownedConnection: null, dirty: false};
let pendingConnection = null;
let submittingPassword = false;
const labels = {
  critical: ["Critical review", "critical"], warning: ["Flagged for review", "flagged"],
  lead: ["Network lead", "lead"], context: ["Verify activity", "context"]
};
const captureOptions = {
  windows: {
    Security: ["Security", "Sign-ins, account activity, and processes when Windows auditing records them."],
    System: ["System", "System and service events, including service installs and startup changes."],
    Application: ["Application", "Messages written by applications to the Windows Application log."],
    TaskScheduler: ["Task Scheduler", "Task registrations, updates, and runs from the Task Scheduler Operational channel."],
    Changes: ["Configuration & tasks", "Selected Security and System changes plus Task Scheduler activity. Requires access to those channels."],
    All: ["All enabled standard channels", "Rotates through enabled classic, Administrative, and Operational logs in groups. Busy or restricted channels can have gaps."]
  },
  linux: {
    Journal: ["All accessible journal entries", "Reads the latest entries the SSH account can see in the systemd journal."],
    Changes: ["Configuration & tasks", "Journal entries for services, cron, sudo, and audit. Audit files outside the journal require a separate export."]
  }
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

function record(title, severity) {
  const [label, style] = labels[severity] ?? [];
  const card = node("article", undefined, style ? `record review-${style}` : "record");
  const header = node("div", undefined, "event-heading");
  header.append(node("h4", title, "record-head"));
  if (label) header.append(node("span", label, `review-badge badge-${style}`));
  card.append(header);
  return card;
}

function renderReview(review) {
  ui.review = review;
  const coverage = $("live-source-coverage");
  coverage.hidden = ui.config?.platform !== "windows" || !["Security", "All"].includes(ui.config.channel);
  if (!coverage.hidden) {
    const count = review.process_creation_events ?? 0;
    const commands = review.process_creation_with_command_line ?? 0;
    coverage.textContent = !count ? "No process-creation events (4688) in the retained buffer. Verify Audit Process Creation on the source if you expect these events."
      : !commands ? `${count} process-creation events received without command lines. Verify “Include command line in process creation events” on the source.`
      : `${count} process-creation events · ${commands} with command lines.`;
  }
  const query = $("live-filter").value.trim().toLowerCase();
  const flaggedOnly = $("live-filter-flags").value === "flagged";
  const matches = event => !query || JSON.stringify(event).toLowerCase().includes(query);
  const evidence = new Map(review.events.map(event => [event.event_id, event]));
  const checked = new Set(review.windows_reviewed_event_ids ?? []);
  const maintenance = new Set(review.maintenance_note_event_ids ?? []);
  const eventCard = event => window.SentinelLogView.logCard(event, {
    severity: review.flagged[event.event_id], checked: true,
    windowsChecked: checked.has(event.event_id), maintenance: maintenance.has(event.event_id),
    blueTeam: review.blue_team_events?.[event.event_id], userAccount: review.user_account_events?.[event.event_id],
    showMessage: true
  });
  const findings = $("live-findings");
  findings.replaceChildren();
  for (const entry of review.findings) {
    const finding = entry.finding;
    if (query && !(entry.title + " " + finding.explanation).toLowerCase().includes(query) &&
        !finding.evidence_event_ids.some(id => evidence.has(id) && matches(evidence.get(id)))) continue;
    if (flaggedOnly && entry.severity === "context") continue;
    const card = record(entry.title ?? "Authentication burst", entry.severity ?? "warning");
    if (entry.maintenance_note) {
      card.querySelector(".event-heading").append(node("span", "Maintenance note", "review-badge badge-context"));
    }
    card.append(node("p", finding.explanation), node("p", finding.timestamp_utc ?? "Unknown time", "small muted"));
    const details = node("details");
    details.append(node("summary", `Supporting records (${finding.evidence_event_ids.length})`));
    details.addEventListener("toggle", () => {
      if (!details.open || details.children.length > 1) return;
      for (const id of finding.evidence_event_ids) {
        const event = evidence.get(id);
        if (event) details.append(eventCard(event));
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
    events.append(eventCard(event));
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
  const reconnect = !data.active && ui.config?.session_bound;
  if (reconnect) ui.config.session_closed = true;
  $("live-start").disabled = !canStart();
  $("live-stop").disabled = !data.active;
  $("live-save").disabled = ui.saving || !data.parsed || ui.savedRevision === data.revision;
  $("live-autosave").disabled = data.active;
  resumeControls();
  connectionControls(data.active);
  $("live-gap").hidden = !data.possible_gap;
  const bookmark = $("live-bookmark-status");
  bookmark.hidden = !data.resume_enabled;
  bookmark.textContent = data.bookmark_lost ? "Saved position unavailable. Check the gap before starting a new bookmark."
    : data.full_resume_page ? "Full page saved. The next pull will continue from the last saved event."
    : data.bookmark_ready ? "Collection position saved."
    : "The first successful read starts a bookmark from the latest records.";
  renderChannels(data.coverage);
  const checked = data.checked_at ? ` · Last completed pull ${new Date(data.checked_at).toLocaleTimeString()}` : "";
  $("live-coverage").textContent = `${data.retained} retained from the latest hour · ${data.age_evicted ?? data.evicted ?? 0} aged out · ${data.capacity_evicted ?? 0} removed by safety caps · ${data.skipped} without a usable identifier`;
  if (data.rejected) $("live-coverage").textContent += ` · ${data.rejected} rejected by the log parser`;
  $("live-status").textContent = [data.stopped, data.error].filter(Boolean).join(" ") ||
    (data.active ? "Watching for log records." : "");
  if (reconnect) $("live-status").textContent += " Select Connect to sign in again.";
  if (data.active) $("live-connect-status").textContent = "SSH connected. Receiving log records.";
  else if (reconnect) $("live-connect-status").textContent = "SSH session closed. Select Connect to sign in again.";
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

function renderChannels(coverage) {
  $("live-channel-coverage").hidden = !coverage;
  if (!coverage) return;
  const {channels, total_channels, observed_channels, capped_channels, unavailable_channels, discovery_errors} = coverage;
  $("live-channel-summary").textContent = `Windows channels · ${observed_channels} of ${total_channels} attempted`;
  const parts = [`Latest pull checked ${channels.length} channels`];
  if (unavailable_channels) parts.push(`${unavailable_channels} unavailable at last attempt`);
  if (capped_channels) parts.push(`${capped_channels} capped at last attempt`);
  if (discovery_errors) parts.push(`${discovery_errors} channel discovery errors`);
  $("live-channel-detail").textContent = parts.join(" · ");
  $("live-channel-list").replaceChildren(...channels.map(entry => {
    const statuses = [{read: "Read", empty: "No matching events", unavailable: "Unavailable"}[entry.status]];
    if (entry.capped) statuses.push("Event cap reached");
    if (entry.dropped) statuses.push(`${entry.dropped} omitted by size limit`);
    if (entry.gap) statuses.push("Possible gap");
    return node("li", `${entry.channel} · ${statuses.join(" · ")}`);
  }));
}

function pollingStatus(text, kind) {
  $("live-poll-state").textContent = text;
  $("live-poll-state").parentElement.dataset.state = kind;
}

function stopViewUpdates() {
  clearTimeout(ui.timer);
  ui.timer = null;
}

function watchPath(action) {
  return `/api/live/${ui.id}/${action}?token=${encodeURIComponent(ui.token ?? "")}`;
}

const watchKey = "sentinel-live-selected-watch";
let running = [];

async function loadRunning(restore = false) {
  const {items} = await request("/api/live/background");
  running = items;
  $("live-running-row").hidden = !items.length;
  $("live-running").replaceChildren(new Option("Set up another watch", ""),
    ...items.map(item => new Option(`${item.host}:${item.port} · ${item.channel}`, item.id)));
  $("live-running").value = items.some(item => item.id === ui.id) ? ui.id : "";
  if (restore && !ui.id) {
    let preferred;
    try { preferred = sessionStorage.getItem(watchKey); } catch {}
    const watch = items.find(item => item.id === preferred);
    if (watch) followWatch(watch);
  }
}

function rememberWatch(id) {
  try {
    if (id) sessionStorage.setItem(watchKey, id);
    else sessionStorage.removeItem(watchKey);
  } catch {}
}

function followWatch(watch) {
  stopViewUpdates();
  ui.sequence++;
  ui.id = watch.id;
  ui.token = watch.token;
  ui.active = true;
  ui.config = {platform: watch.platform, channel: watch.channel, session_bound: true};
  ui.revision = ui.savedRevision = -1;
  ui.review = ui.lastWatch = null;
  ui.ownedConnection = null;
  $("live-running").value = watch.id;
  $("live-target").textContent = `${watch.host}:${watch.port} · ${watch.channel}`;
  for (const id of ["live-findings", "live-events"]) $(id).replaceChildren(node("p", "Loading this watch…", "muted"));
  connectionControls(true);
  $("live-start").disabled = true;
  $("live-save").disabled = true;
  rememberWatch(watch.id);
  updateWatch();
}

$("live-running").addEventListener("change", () => {
  const watch = running.find(item => item.id === $("live-running").value);
  if (watch) followWatch(watch);
  else {
    stopViewUpdates();
    ui.sequence++;
    ui.id = ui.token = ui.review = ui.lastWatch = null;
    ui.ownedConnection = null;
    ui.active = false;
    rememberWatch(null);
    connectionControls(false);
    $("live-stop").disabled = $("live-save").disabled = true;
    $("live-autosave").disabled = false;
    $("live-target").textContent = "Connect a Windows or Linux source.";
    $("live-status").textContent = "Select a running watch or connect another source.";
    for (const id of ["live-findings", "live-events"]) $(id).replaceChildren(node("p", "Select a watch to view records.", "muted"));
    pollingStatus("Not watching", "stopped");
    resumeControls();
  }
});

async function updateWatch() {
  const sequence = ui.sequence;
  try {
    const data = await request(watchPath("view") + (ui.revision >= 0 ? `&revision=${ui.revision}` : ""));
    if (sequence !== ui.sequence) return;
    renderWatch(data);
    if (!data.active) {
      rememberWatch(null);
      await loadRunning();
    }
  } catch (error) {
    if (sequence !== ui.sequence) return;
    $("live-status").textContent = error.message;
    if (error.status === 404) {
      if (ui.lastWatch) renderWatch({...ui.lastWatch, active: false, stopped: error.message});
      else {
        ui.active = false;
        connectionControls(false);
        $("live-stop").disabled = true;
      }
      rememberWatch(null);
    }
  }
  if (sequence === ui.sequence && ui.active) ui.timer = setTimeout(updateWatch, 5000);
}

$("live-start").addEventListener("click", async () => {
  if (!canStart()) return;
  const autosave = $("live-autosave").checked;
  const resume = !$("live-resume").disabled && $("live-resume").checked;
  const restart = resume && $("live-restart").checked;
  if (restart && !window.confirm("Start from the latest records? Any unread history before the new starting point will need a separate export.")) return;
  connectionControls(true);
  ui.starting = true;
  $("live-start").disabled = true;
  $("live-save").disabled = true;
  $("live-open-library").hidden = true;
  try {
    const params = new URLSearchParams({host: ui.config.host, port: ui.config.port});
    const result = await request(`/api/live/start?${params}`, {...post,
      headers: {...post.headers, "Content-Type": "application/json"},
      body: JSON.stringify({autosave, resume, restart_from_latest: restart, connection_id: ui.ownedConnection, background: true})});
    $("live-restart").checked = false;
    ui.id = result.id;
    ui.token = result.token;
    ui.saving = false;
    ui.savedRevision = -1;
    ui.sequence++;
    renderWatch(result);
    rememberWatch(ui.id);
    updateWatch();
    loadRunning().catch(() => {});
  } catch (error) {
    $("live-status").textContent = error.message;
    $("live-start").disabled = !canStart();
    connectionControls(ui.active);
  } finally {
    ui.starting = false;
  }
});

function connectionControls(disabled) {
  for (const control of $("live-connect-form").elements) control.disabled = disabled;
}

function canStart() {
  return Boolean(ui.ownedConnection && !ui.active && !ui.dirty && !ui.config?.password_required && !ui.config?.session_closed);
}

function sourceHelp() {
  $("live-channel-help").textContent = captureOptions[$("live-platform").value][$("live-channel").value]?.[1] ?? "";
  resumeControls();
}

function resumeControls() {
  const supported = $("live-platform").value === "linux" || !["All", "Changes"].includes($("live-channel").value);
  $("live-resume-settings").hidden = !supported;
  $("live-resume").disabled = ui.active || !supported || !$("live-autosave").checked;
  $("live-restart-label").hidden = !$("live-autosave").checked || !$("live-resume").checked;
  $("live-restart").disabled = $("live-resume").disabled;
}

$("live-autosave").addEventListener("change", resumeControls);
$("live-resume").addEventListener("change", resumeControls);

function sourceControls(selected) {
  const choices = captureOptions[$("live-platform").value];
  $("live-channel").replaceChildren(...Object.entries(choices).map(([value, [label]]) => new Option(label, value)));
  if (Object.hasOwn(choices, selected)) $("live-channel").value = selected;
  sourceHelp();
}

$("live-platform").addEventListener("change", () => sourceControls());
$("live-channel").addEventListener("change", sourceHelp);
$("live-connect-form").addEventListener("input", () => {
  if (!ui.ownedConnection) return;
  ui.dirty = true;
  $("live-start").disabled = true;
  $("live-connect-status").textContent = "Select Connect to verify the updated settings.";
});

function renderConfig(config) {
  ui.config = config;
  $("live-start").disabled = !canStart();
  if (config.ready) {
    $("live-ssh").value = `ssh ${config.username}@${config.host} -p ${config.port}`;
    $("live-identity").value = config.identity_file;
    $("live-platform").value = config.platform;
    $("live-authentication").value = config.authentication === "password" ? "password" :
      config.session_bound && config.authentication === "key" ? "key" : $("live-authentication").value;
    sourceControls(config.channel);
    const address = `${config.host}:${config.port}`;
    const source = captureOptions[config.platform][$("live-channel").value][0];
    $("live-target").textContent = ui.ownedConnection
      ? `${address} · ${source} · Checks about every ${config.poll_seconds} seconds`
      : "Select Connect to verify the SSH source for this tab.";
    if (ui.ownedConnection) document.title = `${config.host} · Live logs · Sentinel`;
  }
}

function connected(config) {
  if (ui.ownedConnection && ui.ownedConnection !== config.connection_id) disconnectSource();
  ui.sequence++;
  stopViewUpdates();
  ui.id = null;
  ui.token = null;
  ui.revision = -1;
  ui.review = null;
  ui.lastWatch = null;
  ui.savedRevision = -1;
  ui.ownedConnection = config.connection_id ?? null;
  ui.dirty = false;
  pollingStatus("Not watching", "stopped");
  $("live-poll-detail").textContent = "Start a watch to check for new events.";
  $("live-source-coverage").hidden = true;
  renderChannels(null);
  $("live-gap").hidden = true;
  $("live-bookmark-status").hidden = true;
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
    channel: $("live-channel").value, identity_file: $("live-identity").value, authentication: $("live-authentication").value, isolated: true};
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
    $("live-start").disabled = !canStart();
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
    $("live-start").disabled = !canStart();
    $("live-save").disabled = !ui.id || !ui.review?.events.length || ui.savedRevision === ui.revision;
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
    stopViewUpdates();
    renderWatch(result);
    rememberWatch(null);
    loadRunning().catch(() => {});
  } catch (error) {
    $("live-status").textContent = error.message;
    $("live-stop").disabled = false;
    $("live-start").disabled = !canStart();
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
      ? "Saved and analyzed a capture in Logs. The live watch continues."
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

function disconnectSource() {
  if (ui.ownedConnection) fetch(`/api/live/disconnect?connection_id=${encodeURIComponent(ui.ownedConnection)}`, {...post, keepalive: true}).catch(() => {});
  ui.ownedConnection = null;
  $("live-start").disabled = true;
}

function leaveView() {
  $("live-password").value = "";
  pendingConnection = null;
  ui.sequence++;
  stopViewUpdates();
  if (!ui.active && !ui.starting) disconnectSource();
}

window.addEventListener("pagehide", leaveView);
window.addEventListener("pageshow", event => { if (event.persisted && ui.active) updateWatch(); });
$("live-logout").addEventListener("click", async () => {
  leaveView();
  rememberWatch(null);
  try { await request("/api/auth/logout", post); window.location.replace("/login"); }
  catch (error) { $("live-status").textContent = error.message; }
});

request("/api/auth/me").then(user => {
  $("live-user").textContent = `Signed in as ${user.username}`;
  if (user.role === "teammate") {
    $("live-watch-workspace").hidden = true;
    $("agent-feed").open = true;
  }
}).catch(() => {});
sourceControls();
request("/api/live/status").then(config => {
  if (!ui.active && !ui.ownedConnection && !$("live-ssh").value) renderConfig(config);
}).catch(error => { $("live-target").textContent = error.message; });
loadRunning(true).catch(error => { $("live-status").textContent = error.message; });
