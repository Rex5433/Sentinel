"use strict";
const $ = id => document.getElementById(id);
const {element, request, validId, timelineUrl, eventCard, findingCard} = window.SentinelAgentView;
const labels = Object.freeze({
  disabled: "Disconnected", connecting: "Connecting", connected: "Connected", partial: "Partial collection",
  retrying: "Disconnected · retrying", blocked: "Disconnected · blocked", waiting_for_password: "Password needed"
});
const collectorLabels = Object.freeze({ready: "Ready", empty: "No new events", absent: "Optional · absent",
  gap: "Collection gap", error: "Unavailable", snapshot: "Snapshot received"});
const errorLabels = Object.freeze({
  network: "SSH network", timeout: "SSH timeout", authentication: "SSH authentication", host_key: "SSH host key",
  permission: "Read permission", command: "Collector command", output_limit: "Output limit",
  unavailable: "Unavailable source", disabled_channel: "Disabled channel", processing: "Event processing"
});
const attention = new Set(["partial", "retrying", "blocked", "waiting_for_password"]);
const connected = new Set(["connected", "partial"]);
let catalog;
let hosts = [];
let selected = null;
let hostDetail = null;
let listRequest = 0;
let detailRequest = 0;
let refreshing = false;
let busy = false;
let formBusy = false;
let editingId = null;
let tested = null;
let passwordAction = null;
const pauseKey = "sentinel-agents-paused-views";
let pausedHosts = new Set();
try {
  const ids = JSON.parse(localStorage.getItem(pauseKey) || "[]");
  if (Array.isArray(ids)) pausedHosts = new Set(ids.filter(validId));
} catch {}

function message(text, isError = false) {
  const status = $("agents-status");
  status.textContent = text;
  status.hidden = !text;
  status.classList.toggle("error", isError);
}

function badge(text, flagged) {
  return element("span", text, `review-badge ${flagged ? "badge-flagged" : "badge-neutral"}`);
}

function hostBadges(host) {
  const state = connected.has(host.status) ? "connected" :
    ["disabled", "retrying", "blocked", "waiting_for_password"].includes(host.status) ? "disconnected" : "neutral";
  const status = element("span", state === "connected" ? "Connected" : labels[host.status] ?? "Unknown",
    `review-badge agent-state-${state}`);
  const tags = [status];
  if (host.status === "partial") tags.push(badge("Partial collection", true));
  if (pausedHosts.has(host.id)) tags.push(element("span", "View paused", "review-badge agent-state-paused"));
  if (host.live_capture && host.enabled && connected.has(host.status)) {
    const live = element("span", "Live", "review-badge agent-state-connected");
    live.title = "Collecting and saving live batches to Logs.";
    tags.push(live);
  }
  return tags;
}

function platformLabel(platform) {
  return {windows: "Windows", linux: "Linux"}[platform] ?? "Unknown OS";
}

function duration(seconds) {
  if (!Number.isFinite(seconds)) return "Unknown";
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86400)} d`;
}

function ageSeconds(timestamp) {
  const time = Date.parse(timestamp);
  return Number.isFinite(time) ? Math.max(0, Math.floor((Date.now() - time) / 1000)) : null;
}

function renderHosts(limit) {
  const filters = $("agents-filter").value;
  const search = $("agents-search").value.trim().toLowerCase();
  const visible = hosts.filter(host => [host.name, host.host, host.role, platformLabel(host.platform)]
    .join(" ").toLowerCase().includes(search) && (filters === "all" || (filters === "connected" && connected.has(host.status)) ||
    (filters === "attention" && attention.has(host.status)) || (filters === "disabled" && !host.enabled)));
  const pulls = hosts.map(host => ageSeconds(host.last_success_at)).filter(age => age !== null);
  const delays = hosts.filter(host => host.enabled).map(host => {
    const age = ageSeconds(host.last_success_at);
    return age === null ? null : Math.max(0, age - host.interval_seconds);
  }).filter(delay => delay !== null);
  const counts = [
    [limit ? `${hosts.length}/${limit}` : hosts.length, "Configured"],
    [hosts.filter(host => connected.has(host.status)).length, "Connected"],
    [hosts.filter(host => !connected.has(host.status)).length, "Disconnected"],
    [hosts.filter(host => attention.has(host.status) || host.error).length, "Needs attention"],
    [pulls.length ? `${duration(Math.min(...pulls))} ago` : "None yet", "Last successful pull"],
    [delays.length ? duration(Math.max(...delays)) : "Unknown", "Longest collection delay"],
    [hosts.reduce((total, host) => total + (host.alert_count ?? 0), 0), "Retained flagged events"],
  ];
  $("agents-counts").replaceChildren(...counts.map(([value, title]) => {
    const box = element("div", undefined, "count");
    box.append(element("strong", value), element("span", title));
    return box;
  }));
  const focused = document.activeElement?.dataset.agentId;
  $("agents-list").replaceChildren(...visible.map(host => {
    const button = element("button", undefined, "import-item");
    button.type = "button";
    button.dataset.agentId = host.id;
    button.setAttribute("aria-pressed", String(host.id === selected));
    const heading = element("span", undefined, "agent-host-heading");
    heading.append(element("strong", host.name), ...hostBadges(host));
    button.append(heading, element("small", `${platformLabel(host.platform)} · ${host.alert_count ?? 0} flagged`));
    button.addEventListener("click", () => selectHost(host.id));
    return button;
  }));
  if (!visible.length) $("agents-list").append(element("p", hosts.length ? "No hosts match this filter." : "Add a host to start collecting.", "muted"));
  if (focused) [...$("agents-list").children].find(button => button.dataset.agentId === focused)?.focus({preventScroll: true});
}

function emptyOrCards(container, rows, render, empty) {
  $(container).replaceChildren(...(rows.length ? rows.map(render) : [element("p", empty, "small muted")]));
}

function updateReviewCards(id, rows, keyFor, contentFor, render, empty) {
  const container = $(id);
  const existing = new Map([...container.children].map(card => [card.dataset.reviewKey, card]));
  const desired = rows.map((row, index) => {
    const key = keyFor(row, index);
    const content = contentFor(row);
    const prior = existing.get(key);
    if (prior?.reviewContent === content) return prior;
    const card = render(row);
    card.dataset.reviewKey = key;
    card.reviewContent = content;
    if (prior) {
      const details = [...prior.querySelectorAll(":scope > details")];
      card.querySelectorAll(":scope > details").forEach((item, position) => { item.open = Boolean(details[position]?.open); });
    }
    return card;
  });
  if (!desired.length) {
    if (container.firstChild?.textContent !== empty) container.replaceChildren(element("p", empty, "small muted"));
    return;
  }
  const keep = new Set(desired);
  for (const card of [...container.children]) if (!keep.has(card)) card.remove();
  for (const [index, card] of desired.entries()) {
    if (container.children[index] !== card) container.insertBefore(card, container.children[index] ?? null);
  }
}

function collectorIssue(stream) {
  if (stream.error_kind === "disabled_channel" || stream.error === "This Windows event channel is disabled.") return "Channel disabled";
  if (stream.error_kind === "permission") return "Read permission denied";
  return stream.status === "gap" ? "Collection gap" : errorLabels[stream.error_kind] ?? "Source unavailable";
}

function renderCoverage(host, problems) {
  const notice = $("agent-coverage-notice");
  notice.hidden = host.status !== "partial" || !problems.length;
  if (notice.hidden) return;
  const sources = problems.slice(0, 2).map(stream => `${stream.label ?? stream.id} (${collectorIssue(stream)})`);
  const more = problems.length > sources.length ? ` and ${problems.length - sources.length} more` : "";
  const link = element("a", "View collector details", "small");
  link.href = "#agent-collector-section";
  link.addEventListener("click", () => { $("agent-collector-section").open = true; });
  notice.replaceChildren(document.createTextNode(`Limited coverage · ${sources.join(" · ")}${more}. `), link);
}

function streamCard(stream, host, actions = true) {
  const card = element("article", undefined, "record");
  const title = element("div", undefined, "event-heading");
  title.append(element("h4", stream.label ?? stream.id ?? "Collector", "record-head"),
    badge(collectorLabels[stream.status] ?? "Unknown", ["error", "gap"].includes(stream.status)));
  card.append(title);
  const status = [stream.observed_at, stream.backlog && "More records are waiting",
    stream.snapshot?.limited && "Showing a capped snapshot",
    stream.changed_rows > 0 && `${stream.changed_rows} changed rows since baseline`].filter(Boolean);
  if (status.length) card.append(element("p", status.join(" · "), "small muted"));
  if (stream.error) card.append(element("p", [errorLabels[stream.error_kind], stream.error].filter(Boolean).join(" · "),
    stream.status === "absent" ? "small muted" : "warnings"));
  if (collectorIssue(stream) === "Channel disabled") {
    card.append(element("p", "If this channel is required, have an authorized Windows administrator check it in Event Viewer. If it is intentionally disabled, adjust the host’s collector modules if the other channels in that module are also unnecessary.", "small muted"));
  } else if (stream.error_kind === "permission") {
    card.append(element("p", stream.id?.startsWith("file-")
      ? "If the journal provides the required events, turn off Authentication log files in Edit host. Otherwise have an authorized Linux administrator review this account’s read access."
      : "Have an authorized administrator verify the SSH account’s read access to this source.", "small muted"));
  }
  if (stream.snapshot !== null && stream.snapshot !== undefined) {
    const details = element("details");
    details.append(element("summary", "View snapshot"), element("pre", JSON.stringify(stream.snapshot, null, 2)));
    card.append(details);
  }
  if (actions && stream.id) {
    const link = element("a", "Collector timeline", "small");
    link.href = timelineUrl(host.id, stream.id);
    const line = element("p");
    line.append(link);
    card.append(line);
  }
  if (actions && stream.status === "gap") {
    const reset = element("button", "Resume from available records", "secondary");
    reset.type = "button";
    reset.addEventListener("click", () => {
      if (window.confirm("Resume this collector from the records the host still has? The missing interval remains a collection gap.")) {
        perform(host.id, "reset_gap", {stream_id: stream.id});
      }
    });
    card.append(reset);
  }
  return card;
}

function updateButtons() {
  for (const id of ["agent-connect", "agent-disconnect", "agent-reconnect", "agent-collect", "agent-test-saved", "agent-edit", "agent-remove", "agent-save-logs", "agent-save-live", "agent-purge"]) {
    $(id).disabled = busy || !hostDetail;
  }
  if (!hostDetail || busy) return;
  $("agent-connect").disabled = ["connecting", "connected", "partial"].includes(hostDetail.status);
  $("agent-disconnect").disabled = !hostDetail.enabled;
  $("agent-save-logs").disabled = !(hostDetail.events?.length);
  $("agent-purge").disabled = hostDetail.enabled || !!hostDetail.live_capture || !hostDetail.events?.length;
  $("agent-save-live").disabled = !hostDetail.enabled && !hostDetail.live_capture;
}

let expandedFindings = false;
let expandedEvents = false;
function updatesPaused() { return pausedHosts.has(selected); }

function renderPause(paused) {
  $("agent-pause-updates").textContent = paused ? "Resume updates" : "Pause updates";
  $("agent-review-state").textContent = paused ? "Automatic updates paused for this view. Collection follows the host’s monitoring settings." : "";
}

function renderFindings(host) {
  const severity = {critical: 0, warning: 1, lead: 2, context: 3};
  const criticalOnly = $("agent-findings-filter").value === "critical";
  const findings = (host.findings ?? []).filter(entry => !criticalOnly || entry.severity === "critical")
    .sort((a, b) => (severity[a.severity] ?? 4) - (severity[b.severity] ?? 4));
  const evidence = new Map((host.events ?? []).map(row => [row.event_id, row]));
  updateReviewCards("agent-findings", expandedFindings ? findings : findings.slice(0, 3),
    (entry, index) => `${host.id}:${entry.finding?.finding_id ?? `${entry.title}-${index}`}`, JSON.stringify,
    entry => findingCard(entry, evidence, host), criticalOnly ? "No recent critical findings." : "No recent findings.");
  $("agent-findings-more").hidden = expandedFindings || findings.length <= 3;
  $("agent-findings-more").textContent = `Show all ${findings.length} findings`;
}

function renderEvents(host) {
  const flagged = $("agent-event-filter").value === "flagged";
  const events = (host.events ?? []).filter(event => !flagged || ["critical", "warning", "lead"].includes(event.agent_severity));
  updateReviewCards("agent-events", expandedEvents ? events : events.slice(0, 10), event => event.event_id,
    event => JSON.stringify([event, host.blue_team_events?.[event.event_id], host.user_account_events?.[event.event_id]]),
    event => eventCard(event, host), flagged ? "No flagged events in this recent sample. Check Findings or Host timeline." : "No events collected yet.");
  $("agent-events-more").hidden = expandedEvents || events.length <= 10;
}

$("agent-findings-more").addEventListener("click", () => { expandedFindings = true; if (hostDetail) renderFindings(hostDetail); });
$("agent-findings-filter").addEventListener("change", () => { expandedFindings = false; if (hostDetail) renderFindings(hostDetail); });
$("agent-pause-updates").addEventListener("click", () => {
  if (!validId(selected)) return;
  if (updatesPaused()) pausedHosts.delete(selected);
  else pausedHosts.add(selected);
  try { localStorage.setItem(pauseKey, JSON.stringify([...pausedHosts])); } catch {}
  renderPause(updatesPaused());
  renderHosts(hostLimit);
  if (!updatesPaused()) refresh();
});
$("agent-events-more").addEventListener("click", () => { expandedEvents = true; if (hostDetail) renderEvents(hostDetail); });
$("agent-event-filter").addEventListener("change", () => { expandedEvents = false; if (hostDetail) renderEvents(hostDetail); });

function renderDetail(host, preserveScroll = false) {
  const sameHost = host?.id === hostDetail?.id;
  const position = preserveScroll && sameHost ? window.scrollY : 0;
  const anchor = position && [...document.querySelectorAll("#agent-findings > [data-review-key], #agent-events > [data-review-key]")]
    .find(card => { const box = card.getBoundingClientRect(); return box.bottom > 0 && box.top < window.innerHeight; });
  const anchorTop = anchor ? anchor.getBoundingClientRect().top : 0;
  const previous = hostDetail;
  hostDetail = host;
  $("agent-detail-title").textContent = host?.name || "Host details";
  $("agent-detail-empty").hidden = Boolean(host);
  $("agent-detail").hidden = !host;
  updateButtons();
  if (!sameHost) {
    expandedFindings = expandedEvents = false;
    $("agent-findings-filter").value = "all";
    $("agent-event-filter").value = "all";
  }
  if (!host) return;
  renderPause(pausedHosts.has(host.id));
  $("agent-download-profile").href = `/api/agents/${host.id}/profile`;
  const capture = host.live_capture;
  $("agent-save-live").textContent = capture ? "Stop Live Save" : "Save Live Log";
  const captureStatus = $("agent-capture-status");
  captureStatus.hidden = !capture;
  captureStatus.textContent = capture ? capture.error ?? (host.enabled ?
    "Live save enabled. New evidence is saved to Logs in batches." : "Live save is waiting for this host to reconnect.") : "";
  if (validId(capture?.last_upload_id)) {
    const link = element("a", " Open latest saved batch");
    link.href = `/?${new URLSearchParams({tool: "timeline", upload_id: capture.last_upload_id})}`;
    captureStatus.append(link);
  }
  $("agent-detail-state").replaceChildren(...hostBadges(host));
  const streams = host.streams ?? [];
  const problems = streams.filter(stream => ["error", "gap"].includes(stream.status));
  renderCoverage(host, problems);
  $("agent-detail-error").hidden = !host.error || (host.error_kind === "collector" && !$("agent-coverage-notice").hidden);
  $("agent-detail-error").textContent = host.error ? [errorLabels[host.error_kind], host.error].filter(Boolean).join(" · ") : "";
  const age = ageSeconds(host.last_event_at);
  const metrics = [
    ["SSH target", `${host.username}@${host.host}:${host.port}`],
    ["Operating system", platformLabel(host.platform)],
    ["Collection interval", `${host.interval_seconds} s`],
    ["Last successful collection", host.last_success_at || "None yet"],
    ["Latest event", host.last_event_at || "None yet"],
    ["Age of latest event", age === null ? "Unknown" : duration(age)],
    ["Retained flagged events", host.alert_count ?? 0],
    ["Recent records shown", host.events?.length ?? 0],
  ];
  if (host.role) metrics.splice(2, 0, ["Role", host.role]);
  $("agent-detail-metrics").replaceChildren(...metrics.map(([label, value]) => {
    const item = element("div");
    item.append(element("dt", label), element("dd", value));
    return item;
  }));
  $("agent-open-timeline").href = timelineUrl(host.id);
  $("agent-open-live").href = `/live?${new URLSearchParams({agent: host.id})}#agent-feed`;
  if (!sameHost || JSON.stringify(host.streams) !== JSON.stringify(previous.streams)) {
    $("agent-collectors-summary").textContent = `Collectors (${streams.length})${problems.length ? ` · ${problems.length} need attention` : ""}`;
    emptyOrCards("agent-collectors", streams, stream => streamCard(stream, host), "No collector results yet.");
  }
  if (!sameHost || JSON.stringify(host.history) !== JSON.stringify(previous.history)) {
    emptyOrCards("agent-history", host.history ?? [], entry => {
      const card = element("div", undefined, "record");
      card.append(element("p", [entry.timestamp ?? entry.observed_at ?? entry.at, labels[entry.status] ?? entry.status].filter(Boolean).join(" · "), "small muted"));
      if (entry.message || entry.error) card.append(element("p", entry.message || entry.error));
      return card;
    }, "No connection history yet.");
  }
  const eventsChanged = !sameHost || JSON.stringify(host.events) !== JSON.stringify(previous.events) ||
    JSON.stringify(host.blue_team_events) !== JSON.stringify(previous.blue_team_events) ||
    JSON.stringify(host.user_account_events) !== JSON.stringify(previous.user_account_events);
  if (eventsChanged || JSON.stringify(host.findings) !== JSON.stringify(previous.findings)) {
    renderFindings(host);
  }
  if (eventsChanged) {
    renderEvents(host);
  }
  if (position) {
    const target = anchor && (anchor.isConnected ? anchor : [...document.querySelectorAll("[data-review-key]")]
      .find(card => card.dataset.reviewKey === anchor.dataset.reviewKey));
    window.scrollTo(0, target ? window.scrollY + target.getBoundingClientRect().top - anchorTop : position);
  }
}

let hostLimit;
async function selectHost(id, automatic = false) {
  const seq = ++detailRequest;
  if (hostDetail?.id !== id) renderDetail(null);
  selected = id;
  renderHosts(hostLimit);
  if (!validId(id)) return;
  try {
    const host = await request(`/api/agents/${encodeURIComponent(id)}`);
    if (seq === detailRequest && (!automatic || !updatesPaused())) renderDetail(host, automatic);
  } catch (error) {
    if (seq === detailRequest && (!automatic || !updatesPaused())) message(error.message, true);
  }
}

async function refresh(automatic = false) {
  const seq = ++listRequest;
  refreshing = true;
  try {
    const result = await request("/api/agents");
    if (seq !== listRequest) return;
    hosts = result.items;
    hostLimit = result.limit;
    if (!hosts.some(host => host.id === selected)) selected = hosts[0]?.id ?? null;
    if (automatic && updatesPaused() && hostDetail?.id === selected) {
      renderHosts(hostLimit);
      return;
    }
    await selectHost(selected, automatic);
  } catch (error) {
    if (seq === listRequest) message(error.message, true);
  } finally {
    if (seq === listRequest) refreshing = false;
  }
}

function editorState(text = "", isError = false) {
  $("agent-test-status").textContent = text;
  $("agent-test-status").classList.toggle("error", isError);
}

function updateEditor() {
  $("agent-fields").disabled = formBusy;
  $("agent-cancel").disabled = formBusy;
  $("agent-test").disabled = formBusy;
  $("agent-save").disabled = formBusy || !tested;
}

function invalidateTest() {
  tested = null;
  $("agent-test-details").hidden = true;
  $("agent-test-details").replaceChildren();
  editorState();
  updateEditor();
}

function selectedModules(platform) {
  return [...$("agent-modules").querySelectorAll("input:checked")]
    .filter(input => !platform || input.dataset.platform === platform).map(input => input.value);
}

function updateIntegrity() {
  $("agent-integrity-row").hidden = !selectedModules().some(name => name.includes("integrity"));
}

function fillModules(selection) {
  const platform = $("agent-platform").value;
  const group = os => Object.entries(catalog.modules[os] ?? {}).map(([key, text]) => {
    const label = element("label", undefined, "trust-label");
    const checkbox = element("input");
    checkbox.type = "checkbox";
    checkbox.value = key;
    checkbox.dataset.platform = os;
    checkbox.checked = (selection ?? catalog.defaults[os] ?? []).includes(key);
    checkbox.addEventListener("change", updateIntegrity);
    label.append(checkbox, document.createTextNode(text));
    return label;
  });
  const container = $("agent-modules");
  if (platform === "auto") {
    const options = element("details");
    options.append(element("summary", "Choose collectors by operating system"));
    for (const os of ["windows", "linux"]) {
      const fields = element("fieldset", undefined, "agent-fieldset agent-modules");
      fields.append(element("legend", platformLabel(os)), ...group(os));
      options.append(fields);
    }
    container.replaceChildren(options);
  } else {
    container.replaceChildren(...group(platform));
  }
  updateIntegrity();
}

function updateAuthFields() {
  const method = $("agent-authentication").value;
  $("agent-password-row").hidden = method === "key";
  $("agent-identity-row").hidden = method === "password";
  if (method === "key") $("agent-password").value = "";
}

function fillEditor(host) {
  $("agent-name").value = host?.name ?? "";
  $("agent-role").value = host?.role ?? "";
  $("agent-host").value = host?.host ?? "";
  $("agent-port").value = host?.port ?? 22;
  $("agent-host").readOnly = $("agent-port").readOnly = Boolean(editingId);
  $("agent-username").value = host?.username ?? "";
  $("agent-authentication").value = host?.authentication ?? "auto";
  $("agent-identity-file").value = host?.identity_file ?? "";
  $("agent-password").value = "";
  $("agent-platform").value = host?.platform ?? "auto";
  $("agent-platform").disabled = Boolean(editingId);
  $("agent-interval").value = host?.interval_seconds ?? 60;
  $("agent-enabled").checked = host?.enabled ?? false;
  $("agent-integrity-paths").value = (host?.integrity_paths ?? []).join("\n");
  fillModules(host?.modules);
  updateAuthFields();
  invalidateTest();
}

function openEditor(host = null) {
  if (!catalog || busy) return;
  editingId = host?.id ?? null;
  $("agent-editor-title").textContent = host ? `Edit ${host.name}` : "Add SSH host";
  $("agent-profile-row").hidden = Boolean(editingId);
  $("agent-profile-file").value = "";
  fillEditor(host);
  $("agent-editor").showModal();
}

$("agent-profile-file").addEventListener("change", async () => {
  const input = $("agent-profile-file");
  const file = input.files[0];
  if (!file || editingId || formBusy) return;
  try {
    if (file.size > 16384) throw Error();
    const profile = JSON.parse(await file.text());
    if (input.files[0] !== file || !$("agent-editor").open || editingId || formBusy) return;
    if (profile?.version !== 1 || !["windows", "linux"].includes(profile.platform) ||
        !["auto", "key", "password"].includes(profile.authentication) ||
        !["name", "host", "username"].every(key => typeof profile[key] === "string" && profile[key].trim()) ||
        (profile.role !== undefined && typeof profile.role !== "string") ||
        !Number.isInteger(profile.port) || !Number.isInteger(profile.interval_seconds) ||
        ![profile.modules, profile.integrity_paths].every(items => Array.isArray(items) && items.every(x => typeof x === "string"))) throw Error();
    const {name, host, port, username, platform, authentication, role, interval_seconds, modules, integrity_paths} = profile;
    fillEditor({name, host, port, username, platform, authentication, role, interval_seconds, modules, integrity_paths});
    editorState("Profile loaded. Review the settings, supply local credentials if needed, and select Test connection.");
  } catch {
    editorState("Choose a valid Sentinel host profile JSON file.", true);
  }
});

function draft() {
  const authentication = $("agent-authentication").value;
  const data = {
    name: $("agent-name").value.trim(), host: $("agent-host").value.trim(), port: Number($("agent-port").value),
    username: $("agent-username").value.trim(), authentication, platform: $("agent-platform").value,
    role: $("agent-role").value.trim(), interval_seconds: Number($("agent-interval").value), modules: selectedModules(),
    integrity_paths: $("agent-integrity-row").hidden ? [] : $("agent-integrity-paths").value.split(/\r?\n/).map(line => line.trim()).filter(Boolean),
    enabled: $("agent-enabled").checked
  };
  if (data.platform === "auto") {
    data.auto_modules = {windows: selectedModules("windows"), linux: selectedModules("linux")};
    data.modules = [];
  }
  if (authentication !== "password" && $("agent-identity-file").value.trim()) data.identity_file = $("agent-identity-file").value.trim();
  if (authentication !== "key" && $("agent-password").value) data.password = $("agent-password").value;
  if (editingId) data.agent_id = editingId;
  return data;
}

async function testConnection() {
  if (formBusy || !$("agent-form").reportValidity()) return;
  const data = draft();
  if (!data.name || !data.host || !data.username) return editorState("Enter a display name, host and SSH username.", true);
  if (data.platform !== "auto" && !data.modules.length) return editorState("Select at least one monitoring module.", true);
  if (data.authentication === "password" && !data.password) return editorState("Enter the SSH account password.", true);
  formBusy = true;
  $("agent-password").value = "";
  invalidateTest();
  editorState("Testing the SSH connection and collector permissions…");
  try {
    const result = await request("/api/agents/test", {method: "POST", data, timeout: 120000});
    tested = result.test_id;
    editorState(`SSH connection verified · ${platformLabel(result.platform)}. Review the collector results and save the host.`);
    const details = $("agent-test-details");
    details.hidden = false;
    const fingerprints = (result.fingerprints ?? []).map(value => typeof value === "string" ? value : value.fingerprint)
      .filter(value => /^SHA256:[A-Za-z0-9+/]{43}=?$/.test(value ?? ""));
    if (fingerprints.length) details.append(element("p", `Verified host key ${fingerprints.join(" · ")}`, "small muted"));
    for (const stream of result.streams ?? []) details.append(streamCard(stream, null, false));
  } catch (error) {
    editorState(error.message, true);
  } finally {
    formBusy = false;
    updateEditor();
  }
}

async function saveHost(event) {
  event.preventDefault();
  if (formBusy || !tested) return;
  formBusy = true;
  updateEditor();
  try {
    const path = editingId ? `/api/agents/${encodeURIComponent(editingId)}/edit` : "/api/agents";
    const result = await request(path, {method: "POST", data: {test_id: tested}});
    selected = result?.id ?? editingId;
    $("agent-editor").close();
    message("Host saved.");
    await refresh();
  } catch (error) {
    editorState(error.message, true);
  } finally {
    formBusy = false;
    updateEditor();
  }
}

async function perform(id, action, extra = {}) {
  if (busy || !validId(id)) return;
  busy = true;
  updateButtons();
  try {
    const path = `/api/agents/${encodeURIComponent(id)}`;
    if (action === "remove") {
      await request(path, {method: "DELETE"});
      pausedHosts.delete(id);
      try { localStorage.setItem(pauseKey, JSON.stringify([...pausedHosts])); } catch {}
      message("Host removed. Collected evidence is still in the Timeline.");
    } else if (action === "capture-start" || action === "capture-stop") {
      const start = action === "capture-start";
      await request(`${path}/capture/${start ? "start" : "stop"}`, {method: "POST", timeout: 120000});
      message(start ? "Live save enabled." : "Live save stopped.");
    } else if (action === "save") {
      const result = await request(`${path}/save`, {method: "POST"});
      message("Snapshot saved to Logs.");
      if (validId(result?.upload_id)) {
        const link = element("a", " View snapshot in Timeline");
        link.href = `/?${new URLSearchParams({tool: "timeline", upload_id: result.upload_id})}`;
        $("agents-status").append(link);
      }
    } else {
      await request(`${path}/action`, {method: "POST", data: {action, ...extra}, timeout: 120000});
      message({connect: "Monitoring enabled.", disconnect: "Monitoring paused.", reconnect: "Reconnection requested.",
        collect: "Collection requested.", reset_gap: "Collector restart requested.", purge: "Retained events and findings cleared."}[action] ?? "");
    }
    await refresh();
  } catch (error) {
    message(error.message, true);
  } finally {
    busy = false;
    updateButtons();
  }
}

function hostAction(action) {
  if (!hostDetail || busy) return;
  const host = hostDetail;
  if (action === "remove" && !window.confirm(`Remove “${host.name}” from monitoring? Its collected evidence will be kept.`)) return;
  if (action === "purge" && !window.confirm(`Permanently clear the events and findings retained for “${host.name}”? Saved Logs snapshots will be kept.`)) return;
  if (action === "collect" && !host.enabled && !window.confirm(`Enable scheduled monitoring for “${host.name}” and collect now?`)) return;
  const needsPassword = (["connect", "reconnect", "collect"].includes(action) &&
    host.authentication === "auto" && ["waiting_for_password", "blocked"].includes(host.status) &&
    ["authentication", "password_required"].includes(host.error_kind)) ||
    (host.authentication === "password" && (["connect", "reconnect"].includes(action) ||
    (action === "collect" && (!host.enabled || host.status === "waiting_for_password"))));
  if (needsPassword) {
    passwordAction = {id: host.id, action};
    $("agent-password-title").textContent = `SSH password for ${host.name}`;
    $("agent-password-dialog").showModal();
    return;
  }
  perform(host.id, action);
}

$("agent-password-form").addEventListener("submit", event => {
  event.preventDefault();
  if (!passwordAction) return;
  const {id, action} = passwordAction;
  const password = $("agent-connect-password").value;
  $("agent-password-dialog").close();
  perform(id, action, {password});
});
$("agent-password-dialog").addEventListener("close", () => {
  passwordAction = null;
  $("agent-connect-password").value = "";
});
$("agent-password-cancel").addEventListener("click", () => $("agent-password-dialog").close());

$("agents-add").addEventListener("click", () => openEditor());
$("agents-refresh").addEventListener("click", () => refresh());
$("agents-filter").addEventListener("change", () => renderHosts(hostLimit));
$("agents-search").addEventListener("input", () => renderHosts(hostLimit));
$("agent-test-saved").addEventListener("click", () => {
  if (!hostDetail || busy || !catalog) return;
  openEditor(hostDetail);
  if (hostDetail.authentication !== "password") testConnection();
  else {
    editorState("Enter the SSH account password to test this host.");
    $("agent-password").focus();
  }
});
$("agent-edit").addEventListener("click", () => openEditor(hostDetail));
$("agent-form").addEventListener("submit", saveHost);
$("agent-form").addEventListener("input", invalidateTest);
$("agent-platform").addEventListener("change", () => fillModules());
$("agent-authentication").addEventListener("change", updateAuthFields);
$("agent-test").addEventListener("click", testConnection);
$("agent-cancel").addEventListener("click", () => $("agent-editor").close());
$("agent-editor").addEventListener("cancel", event => { if (formBusy) event.preventDefault(); });
$("agent-editor").addEventListener("close", () => {
  $("agent-password").value = "";
  invalidateTest();
});
for (const action of ["connect", "disconnect", "reconnect", "collect", "remove", "purge"]) {
  $(`agent-${action}`).addEventListener("click", () => hostAction(action));
}
$("agent-save-logs").addEventListener("click", () => hostAction("save"));
$("agent-save-live").addEventListener("click", () => {
  if (hostDetail) perform(hostDetail.id, hostDetail.live_capture ? "capture-stop" : "capture-start");
});
$("agents-logout").addEventListener("click", async () => {
  try {
    await request("/api/auth/logout", {method: "POST"});
    window.location.replace("/login");
  } catch (error) {
    message(error.message, true);
  }
});
request("/api/auth/me").then(user => {
  $("agents-user").textContent = `Signed in as ${user.username}`;
  if (user.role === "teammate") {
    for (const id of ["agents-add", "agent-connect", "agent-disconnect", "agent-reconnect", "agent-collect",
      "agent-test-saved", "agent-edit", "agent-download-profile", "agent-remove", "agent-save-live", "agent-purge"]) $(id).hidden = true;
  }
}).catch(() => {});
request("/api/agents/modules").then(result => {
  catalog = result;
  $("agents-add").disabled = false;
}).catch(error => message(error.message, true));
const initialAgent = new URLSearchParams(window.location.search).get("agent");
if (validId(initialAgent)) selected = initialAgent;
refresh();
setInterval(() => {
  if (!refreshing && !busy && !document.hidden && !$("agent-editor").open && !$("agent-password-dialog").open) refresh(true);
}, 10000);
