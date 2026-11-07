"use strict";
const $ = (id) => document.getElementById(id);
const defaultPageSize = 10;
const state = { selected: null, offset: 0, pageSize: defaultPageSize, lastOffset: 0, sequence: 0, analysisSequence: 0, overviewSequence: 0, networkSequence: 0, analysis: null, overview: null, busy: false, mode: "import", filters: {}, ask: null, commandSequence: 0, networkFilters: {}, networkFlowId: null };
const formatNames = { "windows-json": "Windows JSON", "windows-jsonl": "Windows JSON Lines", "windows-csv": "Windows CSV", "linux-text": "Linux syslog", "linux-journal-json": "Linux journal JSON Lines" };
const tools = {
  logs: ["Log review", "Findings and the events that support them."],
  network: ["Network captures", "Inspect packet headers and directional flows."],
  timeline: ["Event timeline", "Search and filter events across saved logs."],
  commands: ["Command reference", "Read-only Windows and Linux commands to copy and run manually."]
};
let activeTool = "logs";
let modelLabAvailable = false;

let modelReview = null;

function setImportOpen(open) {
  $("import-panel").hidden = !open;
  const button = $("add-import");
  button.setAttribute("aria-expanded", String(open));
  button.classList.toggle("secondary", open);
  button.textContent = open ? "Close import" : activeTool === "network" ? "Add capture" : "Add logs";
}

function showTool(tool) {
  activeTool = tool;
  const library = tool === "logs" || tool === "network";
  const [title, description] = tools[tool];
  $("tool-title").textContent = title;
  $("tool-description").textContent = description;
  $("library-title").textContent = tool === "network" ? "Saved captures" : "Saved logs";
  $("import-button").textContent = tool === "network" ? "Upload capture" : "Upload & analyze";
  $("add-import").hidden = !library;
  $("library-sidebar").hidden = !library;
  $("blue-team-roster").hidden = tool !== "logs";
  $("work-area").classList.toggle("single-column", !library);
  $("work-area").hidden = tool === "commands";
  $("command-panel").hidden = tool !== "commands";
  $("timeline-search").hidden = tool !== "timeline";
  $("paste-area").hidden = tool !== "logs";
  $("model-review-panel").hidden = tool !== "logs" || !modelLabAvailable;
  setImportOpen(library && !$("import-panel").hidden);
  for (const button of document.querySelectorAll("[data-tool]")) {
    if (button.dataset.tool === tool) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
}

async function openLibrary(tool) {
  const sameType = state.selected && (state.selected.format === "pcap") === (tool === "network");
  if (sameType) return selectImport(state.selected);
  state.mode = "import";
  state.selected = null;
  state.analysis = null;
  state.sequence++;
  state.offset = 0;
  state.lastOffset = 0;
  showTool(tool);
  showSummary();
  setImportOpen(true);
  $("file-panel").open = tool === "network";
  try { await loadImports(); } catch (error) { $("library-status").textContent = error.message; }
}

function modelImport() {
  return state.mode === "import" && state.selected?.format !== "pcap" ? state.selected : null;
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function libraryAction(label, kind, shape) {
  const button = element("button", undefined, `library-action library-${kind} secondary`);
  button.type = "button";
  button.disabled = state.busy;
  button.setAttribute("aria-label", label);
  button.title = label;
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("viewBox", "0 0 24 24");
  icon.setAttribute("aria-hidden", "true");
  icon.setAttribute("focusable", "false");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", shape);
  icon.append(path);
  button.append(icon);
  return button;
}
async function api(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  if (response.status === 401) {
    window.location.replace("/login");
    throw new Error("Your session ended. Sign in again.");
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status}).`;
    try { const body = await response.json(); if (typeof body.detail === "string") detail = body.detail; } catch (_) {}
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

const blueTeamPath = "/api/blue-team/accounts";
async function loadBlueTeamAccounts() {
  const {items} = await api(blueTeamPath);
  const list = $("blue-team-list");
  list.replaceChildren();
  if (!items.length) list.append(element("p", "No accounts on the roster.", "small muted"));
  for (const account of items) {
    const row = element("div", undefined, "blue-team-row");
    const label = `${account.account} · ${account.host} · ${account.platform}`;
    const remove = element("button", "Remove", "secondary");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${label}`);
    remove.addEventListener("click", async () => {
      remove.disabled = true;
      try {
        await api(`${blueTeamPath}/${account.id}`, {method: "DELETE", headers: {"X-Sentinel-Import": "1"}});
        $("blue-team-status").textContent = "Account removed.";
        await Promise.all([loadBlueTeamAccounts(), loadRecords()]);
      } catch (error) {
        $("blue-team-status").textContent = error.message;
        remove.disabled = false;
      }
    });
    row.append(element("span", label), remove);
    list.append(row);
  }
}
$("blue-team-roster").addEventListener("toggle", () => {
  if ($("blue-team-roster").open) loadBlueTeamAccounts().catch(error => {
    $("blue-team-status").textContent = error.message;
  });
});
$("blue-team-form").addEventListener("submit", async event => {
  event.preventDefault();
  const submit = event.currentTarget.querySelector("button[type=submit]");
  submit.disabled = true;
  try {
    const body = {platform: $("blue-team-platform").value, host: $("blue-team-host").value,
      account: $("blue-team-account").value};
    await api(blueTeamPath, {method: "POST", headers: {"X-Sentinel-Import": "1", "Content-Type": "application/json"},
      body: JSON.stringify(body)});
    $("blue-team-account").value = "";
    $("blue-team-status").textContent = "Roster saved.";
    await Promise.all([loadBlueTeamAccounts(), loadRecords()]);
  } catch (error) { $("blue-team-status").textContent = error.message; }
  finally { submit.disabled = false; }
});
function updatePageControls() {
  $("page-size").disabled = state.busy;
  $("first").disabled = $("previous").disabled = state.busy || state.offset === 0;
  $("next").disabled = $("last").disabled = state.busy || state.offset >= state.lastOffset;
}
function setBusy(busy) {
  $("lab-ssh-fetch").disabled = busy;
  for (const id of ["paste-name", "paste-platform", "paste-text", "paste-button", "paste-clear"]) $(id).disabled = busy;
  state.busy = busy;
  for (const id of ["add-import", "import-button", "file", "record-kind", "analyze-button", "ask-button", "ask-query", "ask-scope", "network-kind", "packet-status", "clear-network-filters"]) $(id).disabled = busy;
  document.querySelectorAll(".import-item, .library-action, [data-tool]").forEach((button) => { button.disabled = busy; });
  updatePageControls();
}
function status(text, error = false) {
  $("import-status").textContent = text;
  $("import-status").className = error ? "error" : "";
}
async function loadImports() {
  const tool = activeTool;
  const result = await api("/api/uploads?limit=100");
  for (let offset = result.items.length; offset < result.total; offset += 100) {
    const page = await api(`/api/uploads?limit=100&offset=${offset}`);
    result.items.push(...page.items);
  }
  if (activeTool !== tool) return;
  $("imports").replaceChildren();
  const items = result.items.filter((item) => item.format !== "snapshot" && (item.format === "pcap") === (tool === "network"));
  if (!items.length) $("imports").append(element("p", tool === "network" ? "No saved captures." : "No saved logs.", "muted"));
  for (const item of items) {
    const button = element("button", undefined, "import-item");
    button.type = "button";
    button.disabled = state.busy;
    button.setAttribute("aria-pressed", String(state.selected?.id === item.id));
    button.append(element("span", item.filename), element("small", item.format === "pcap" ? `${item.accepted_count} decoded packets` : `${item.accepted_count} events`));
    button.addEventListener("click", () => selectImport(item));
    const row = element("div", undefined, "library-row");
    const actions = element("div", undefined, "library-actions");
    if (item.format !== "pcap") {
      const edit = libraryAction(`Edit a copy of ${item.filename}`, "edit", "M14 5l5 5M4 20l5-1L21 7l-4-4L5 15z");
      edit.addEventListener("click", () => editImport(item));
      actions.append(edit);
    }
    const remove = libraryAction(`Delete ${item.filename}`, "delete", "M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7");
    remove.addEventListener("click", () => deleteImport(item));
    actions.append(remove);
    row.append(button, actions);
    $("imports").append(row);
  }
}

window.addEventListener("focus", () => {
  if (!state.busy && (activeTool === "logs" || activeTool === "network")) {
    loadImports().catch(error => { $("library-status").textContent = error.message; });
  }
});
function showSummary() {
  modelReview?.select(modelImport());
  const item = state.selected;
  const timeline = state.mode === "timeline";
  const searching = state.mode === "ask";
  const aggregate = timeline || searching;
  const capture = !aggregate && item?.format === "pcap";
  if (aggregate) showTool("timeline");
  $("preview-title").textContent = searching ? "Search results" : timeline ? "Events in UTC" : activeTool === "network" ? "Capture review" : "Review";
  $("preview-title").classList.toggle("visually-hidden", !aggregate);
  $("timeline-filters").hidden = !timeline;
  $("timeline-filter-panel").hidden = !timeline;
  for (const id of ["kind-control", "import-details", "analysis-panel"]) $(id).hidden = aggregate;
  $("import-overview").hidden = aggregate || !item || capture;
  $("network-summary").hidden = !capture; $("network-controls").hidden = !capture;
  if (capture) { $("analysis-panel").hidden = true; $("kind-control").hidden = true; }
  $("empty-state").hidden = aggregate || !!item;
  $("selected-import").hidden = !aggregate && !item;
  $("empty-state").querySelector("h3").textContent = activeTool === "network" ? "Choose a saved capture" : "Choose a saved log";
  $("empty-state").querySelector("p").textContent = activeTool === "network" ? "Or upload a classic PCAP file." : "Or add a log to see a review here.";
  $("ask-scope").options[0].disabled = !item || item.format === "pcap";
  if (!item || item.format === "pcap") $("ask-scope").value = "all";
  if (searching) { $("import-name").textContent = state.ask?.upload_id ? `Selected import: ${state.ask.filename}` : "All saved imports · UTC order, unknown times last"; return; }
  if (timeline) { $("import-name").textContent = `${state.filters.finding_id ? "Finding evidence" : state.filters.upload_id ? `Import ${state.filters.upload_id}` : "All imported log events"} · UTC order, unknown times last`; return; }
  if (!item) return;
  if (!capture) renderAnalysisStatus();
  $("import-name").textContent = item.filename;
  $("report-json").href = `/api/reports/${item.id}?format=json`;
  $("report-text").href = `/api/reports/${item.id}?format=text`;
  $("counts").replaceChildren();
  for (const [number, label] of [[item.accepted_count, capture ? "decoded packets" : "parsed"], [item.rejected_count, capture ? "not decoded" : "rejected"], [item.warning_count, "with warnings"]]) {
    const card = element("div", undefined, "count");
    card.append(element("strong", String(number)), element("span", label));
    $("counts").append(card);
  }
  $("provenance").replaceChildren();
  for (const [label, value] of [["SHA-256", item.sha256], ["Import ID", item.id], ["Format", item.format], ["Imported at (UTC)", item.created_at], ["Original bytes", String(item.byte_count)]]) {
    $("provenance").append(element("dt", label), element("dd", value));
  }
}
async function loadRecords() {
  const item = state.selected;
  const timeline = state.mode === "timeline";
  const searching = state.mode === "ask";
  const capture = !timeline && !searching && item?.format === "pcap";
  if (!item && !timeline && !searching) return;
  const sequence = ++state.sequence;
  const kind = capture ? $("network-kind").value : timeline || searching ? "events" : $("record-kind").value;
  const limit = state.pageSize;
  const offset = state.offset;
  const path = capture ? networkPath(item.id, kind) : searching ? "" : timeline ? `/api/timeline?${new URLSearchParams(state.filters)}&` :
    ["events", "features", "findings"].includes(kind) ? `/api/${kind}?upload_id=${item.id}&include_flags=true&` : `/api/uploads/${item.id}/rejected?`;
  $("record-pages").hidden = true;
  $("preview-error").textContent = "";
  $("records").replaceChildren(element("p", "Loading records…", "muted"));
  try {
    const result = searching ? await api("/api/ask", {method: "POST", headers: {"Content-Type": "application/json", "X-Sentinel-Import": "1"}, body: JSON.stringify({query: state.ask.query, upload_id: state.ask.upload_id, offset, limit})}) : await api(`${path}offset=${offset}&limit=${limit}`);
    if (sequence !== state.sequence) return;
    const pageCount = Math.ceil(result.total / limit);
    state.lastOffset = Math.max(0, pageCount - 1) * limit;
    if (offset > state.lastOffset) {
      state.offset = state.lastOffset;
      await loadRecords();
      return;
    }
    $("page-status").textContent = result.total
      ? `Page ${offset / limit + 1} of ${pageCount} · ${offset + 1}–${Math.min(offset + limit, result.total)} of ${result.total}`
      : "0 records";
    $("record-pages").hidden = result.total <= defaultPageSize;
    updatePageControls();
    $("records").replaceChildren();
    if (capture) {
      for (const record of result.items) $("records").append(kind === "findings" ? networkFindingCard(record) : kind === "flows" ? flowCard(record) : packetCard(record));
      if (!result.items.length) $("records").append(element("p", "No network records match this view. Check coverage and filters; this does not establish safety.", "muted"));
      return;
    }
    if (searching) {
      $("ask-status").textContent = result.message;
      $("records").append(element("p", `${result.scope.description} · ${result.message}`, "request-context"));
      if (!result.supported) { $("page-status").textContent = "Unsupported request"; return; }
      $("records").append(element("pre", `Applied exact filters: ${JSON.stringify(result.applied_filters, null, 2)}`));
      appendCommandLinks($("records"), result.command_ids);
    }
    if (!result.items.length) {
      const empty = kind === "findings" ? "No supported rule matched. This does not establish safety." :
        kind === "features" ? "No eligible feature windows. Check missing-host/time coverage above." :
        searching || timeline ? "No parsed records match these criteria. This does not establish safety." : `No ${kind === "events" ? "parsed events" : "rejected records"} in this import.`;
      $("records").append(element("p", empty, "muted"));
    }
    const flagged = new Set(result.flagged_event_ids ?? []);
    const critical = new Set(result.critical_event_ids ?? []);
    const networkLeads = new Set(result.network_lead_event_ids ?? []);
    const contextReview = new Set(result.context_review_event_ids ?? []);
    const windowsReviewed = new Set(result.windows_reviewed_event_ids ?? []);
    for (const record of result.items) {
      if (kind === "features") { $("records").append(featureCard(record)); continue; }
      if (kind === "findings") { $("records").append(findingCard(record, item.id)); continue; }
      if (kind === "events") {
        $("records").append(logCard(record, {
          severity: critical.has(record.event_id) ? "critical" : flagged.has(record.event_id) ? "warning" :
            networkLeads.has(record.event_id) ? "lead" : contextReview.has(record.event_id) ? "context" : null,
          checked: !timeline && !searching && state.analysis?.status === "current",
          windowsChecked: windowsReviewed.has(record.event_id),
          maintenance: hasMaintenanceNote(result, record),
          blueTeam: result.blue_team_events?.[record.event_id]
        }));
        continue;
      }
      const card = element("article", undefined, "record");
      card.append(element("div", `#${record.record_index} · Unreadable record`, "record-head"), element("p", record.reason, "warnings"));
      const details = element("details");
      details.append(element("summary", "Original evidence and normalized fields"), element("pre", JSON.stringify(record, null, 2)));
      card.append(details); $("records").append(card);
    }
  } catch (error) {
    if (sequence !== state.sequence) return;
    $("records").replaceChildren(); $("preview-error").textContent = error.message;
  }
}
async function selectImport(item) {
  state.sequence++; state.mode = "import"; state.selected = item; state.analysis = null; state.overview = null; state.offset = 0; $("record-kind").value = "events";
  showTool(item.format === "pcap" ? "network" : "logs");
  setImportOpen(false);
  showSummary();
  $("overview-body").textContent = "Loading observed activity…";
  resetNetwork(); $("ask-scope").value = item.format === "pcap" ? "all" : "selected";
  try {
    await loadImports();
    await loadSelectedContext();
    if (state.selected?.id !== item.id || state.mode !== "import") return;
    if (state.analysis?.status === "current" && state.analysis.finding_count) $("record-kind").value = "findings";
    await loadRecords();
  } catch (error) { $("preview-error").textContent = error.message; }
}

$("add-import").addEventListener("click", () => {
  setImportOpen($("import-panel").hidden);
  if ($("import-panel").hidden) return;
  $("file-panel").open = activeTool === "network";
  $(activeTool === "network" ? "file" : "paste-name").focus();
});
for (const tool of ["logs", "network"]) {
  document.querySelector(`[data-tool="${tool}"]`).addEventListener("click", () => openLibrary(tool));
}
function importSummary(item) {
  return item.format === "pcap"
    ? `Saved capture · ${item.accepted_count} decoded packets · ${item.rejected_count} not decoded.`
    : `${formatNames[item.format]} · ${item.accepted_count} parsed · ${item.rejected_count} rejected · ${item.warning_count} with warnings.`;
}
$("import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("file").files[0];
  if (!file) return status("Choose an export file first.", true);
  if (file.size > 25 * 1024 * 1024) return status("The file exceeds 25 MiB.", true);
  setBusy(true); status("Importing and parsing locally…");
  try {
    const params = new URLSearchParams({ filename: file.name });
    const item = await api(`/api/uploads?${params}`, { method: "POST", headers: { "Content-Type": "application/octet-stream", "X-Sentinel-Import": "1" }, body: file });
    await selectImport(item);
    $("library-status").textContent = importSummary(item);
    if (item.format !== "pcap") await runChecks(item);
    $("import-name").focus();
  } catch (error) { status(error.message, true); }
  finally { setBusy(false); }
});
$("quick-log-commands").addEventListener("toggle", async () => {
  const copy = $("copy-windows-paste-command");
  if (!$("quick-log-commands").open || !copy.disabled) return;
  try {
    const {item} = await api("/api/commands/windows-security-jsonl");
    $("windows-paste-command").textContent = item.command;
    copy.disabled = false;
  } catch (error) {
    $("windows-paste-command").textContent = error.message;
  }
});
document.querySelectorAll("[data-copy-log-command]").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($(button.dataset.copyLogCommand).textContent);
      $("log-command-status").textContent = "Command copied. Run it manually on the authorized host.";
    } catch (_) {
      $("log-command-status").textContent = "Select and copy the command text above.";
    }
  });
});
async function mountLabSsh() {
  const endpoint = "/api/collect/linux";
  const config = await api(endpoint + "/status");
  if (!config.enabled) return;
  $("lab-ssh-panel").hidden = false;
  if (!config.ready) {
    $("lab-ssh-target").textContent = config.detail;
    return;
  }
  $("lab-ssh-target").textContent = `Read up to ${config.max_records} recent entries from ${config.host}:${config.port}. The export is saved in this log library.`;
  const button = $("lab-ssh-fetch");
  button.hidden = false;
  button.addEventListener("click", async () => {
    if (state.busy) return;
    setBusy(true);
    $("lab-ssh-status").textContent = "Reading the configured lab journal…";
    try {
      const query = new URLSearchParams({host: config.host, port: config.port});
      const item = await api(`${endpoint}?${query}`, {method: "POST", headers: {"X-Sentinel-Import": "1"}});
      await selectImport(item);
      $("lab-ssh-status").textContent = importSummary(item);
      $("library-status").textContent = importSummary(item);
      await runChecks(item);
    } catch (error) { $("lab-ssh-status").textContent = error.message; }
    finally { setBusy(false); }
  });
}
mountLabSsh().catch(error => { $("preview-error").textContent = error.message; });
$("paste-clear").addEventListener("click", () => { $("paste-text").value = ""; $("paste-status").textContent = "Text box cleared. Saved imports remain in the library."; });
$("paste-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = $("paste-text").value;
  if (!text.trim()) { $("paste-status").textContent = "Paste log text first."; return; }
  const body = new TextEncoder().encode(text);
  if (body.byteLength > 1024 * 1024) { $("paste-status").textContent = "Pasted text exceeds 1 MiB UTF-8. Use file import for larger exports."; return; }
  const platform = $("paste-platform").value;
  setBusy(true); $("paste-status").textContent = "Inspecting pasted logs locally…";
  try {
    const params = new URLSearchParams({platform, filename: `pasted-${platform}.txt`});
    const name = $("paste-name").value.trim();
    if (name) params.set("name", name);
    const item = await api(`/api/uploads?${params}`, {method: "POST", headers: {"Content-Type": "text/plain", "X-Sentinel-Import": "1"}, body});
    await selectImport(item);
    $("paste-form").reset();
    $("paste-status").textContent = "";
    $("library-status").textContent = importSummary(item);
    await runChecks(item);
    $("import-name").focus();
  } catch (error) { $("paste-status").textContent = error.message; }
  finally { setBusy(false); }
});
let editingLog = null;
let savingEdit = false;

async function editImport(item) {
  if (state.busy) return;
  setBusy(true);
  try {
    const source = await api(`/api/uploads/${item.id}/text`);
    editingLog = source;
    $("edit-log-source").textContent = `Editing a copy of “${source.filename}”. The original saved log and its results stay unchanged.`;
    $("edit-log-name").value = `${source.filename.slice(0, 71)} (edited)`;
    $("edit-log-text").value = source.text;
    $("edit-log-status").textContent = "";
    $("edit-log-dialog").showModal();
  } catch (error) { $("library-status").textContent = error.message; }
  finally { setBusy(false); }
}

$("edit-log-cancel").addEventListener("click", () => $("edit-log-dialog").close());
$("edit-log-dialog").addEventListener("cancel", event => { if (savingEdit) event.preventDefault(); });
$("edit-log-dialog").addEventListener("close", () => { editingLog = null; $("edit-log-form").reset(); });
$("edit-log-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (savingEdit || !editingLog) return;
  const data = new TextEncoder().encode($("edit-log-text").value);
  if (!data.length || data.byteLength > 1024 * 1024) {
    $("edit-log-status").textContent = "Enter nonempty log text up to 1 MiB UTF-8.";
    return;
  }
  const params = new URLSearchParams({platform: editingLog.platform, filename: `edited-${editingLog.platform}.txt`, name: $("edit-log-name").value.trim()});
  savingEdit = true;
  setBusy(true);
  for (const control of $("edit-log-form").elements) control.disabled = true;
  $("edit-log-status").textContent = "Saving and checking the edited copy…";
  try {
    const item = await api(`/api/uploads?${params}`, {method: "POST", headers: {"Content-Type": "text/plain", "X-Sentinel-Import": "1"}, body: data});
    $("edit-log-dialog").close();
    await selectImport(item);
    $("library-status").textContent = `Saved edited copy “${item.filename}”.`;
    await runChecks(item);
    $("import-name").focus();
  } catch (error) { $("edit-log-status").textContent = error.message; }
  finally {
    savingEdit = false;
    setBusy(false);
    for (const control of $("edit-log-form").elements) control.disabled = false;
  }
});

async function deleteImport(item) {
  if (state.busy || !window.confirm(`Delete “${item.filename}” from this library? This removes its saved copy and review results.`)) return;
  setBusy(true);
  try {
    await api(`/api/uploads/${item.id}`, { method: "DELETE", headers: { "X-Sentinel-Import": "1" } });
    if (state.selected?.id === item.id) {
      state.selected = null; state.analysis = null; state.overview = null; state.sequence++; state.analysisSequence++; state.overviewSequence++; state.networkSequence++; state.offset = 0; state.lastOffset = 0; showSummary();
    }
    $("library-status").textContent = `Deleted “${item.filename}”.`;
    await loadImports();
  } catch (error) { $("library-status").textContent = error.message; }
  finally { setBusy(false); }
}
$("record-kind").addEventListener("change", () => { state.offset = 0; loadRecords(); });
$("timeline-button").addEventListener("click", () => { state.mode = "timeline"; state.filters = {}; $("timeline-filters").reset(); state.offset = 0; showSummary(); loadRecords(); });
$("timeline-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  const {upload_id, finding_id} = state.filters;
  state.filters = upload_id ? {upload_id} : {};
  if (finding_id) state.filters.finding_id = finding_id;
  for (const [id, key] of [["filter-host", "host"], ["filter-platform", "platform"], ["filter-type", "event_type"], ["filter-source", "source"], ["filter-actor", "actor"], ["filter-ip", "source_ip"], ["filter-code", "windows_event_id"], ["filter-service", "service"]]) {
    if ($(id).value) state.filters[key] = $(id).value;
  }
  for (const key of ["start", "end"]) if ($(`filter-${key}`).value) state.filters[key] = `${$(`filter-${key}`).value}Z`;
  state.offset = 0; loadRecords();
});
$("clear-filters").addEventListener("click", () => { $("timeline-filters").reset(); state.filters = {}; state.offset = 0; showSummary(); loadRecords(); });
function goToPage(offset) {
  state.offset = offset;
  loadRecords();
}
$("page-size").addEventListener("change", () => {
  state.pageSize = Number($("page-size").value);
  goToPage(0);
});
$("first").addEventListener("click", () => goToPage(0));
$("previous").addEventListener("click", () => goToPage(Math.max(0, state.offset - state.pageSize)));
$("next").addEventListener("click", () => goToPage(Math.min(state.lastOffset, state.offset + state.pageSize)));
$("last").addEventListener("click", () => goToPage(state.lastOffset));
loadImports().catch((error) => { $("imports").replaceChildren(element("p", error.message, "error")); });
api("/api/auth/me").then((user) => { $("signed-in-user").textContent = `Signed in as ${user.username}`; }).catch(() => {});
$("logout-button").addEventListener("click", async () => {
  $("logout-button").disabled = true;
  try {
    await api("/api/auth/logout", {method: "POST", headers: {"X-Sentinel-Import": "1"}});
    window.location.replace("/login");
  } catch (error) { status(error.message, true); $("logout-button").disabled = false; }
});

function renderAnalysisStatus() {
  const result = state.analysis;
  const current = result?.status === "current";
  $("features-option").disabled = !current; $("findings-option").disabled = !current;
  $("analyze-button").textContent = current ? "Run checks again" : "Run checks";
  $("analyze-button").hidden = current;
  $("analysis-panel").dataset.review = "idle";
  $("coverage-status").textContent = "";
  if (!result || result.status === "not_run") {
    $("analysis-status").textContent = "Run checks to look for supported suspicious patterns.";
  } else if (result.status === "stale") {
    $("analysis-status").textContent = "Run checks again to refresh these results.";
  } else {
    const c = result.coverage;
    const unknown = state.overview?.unknown_activity ?? 0;
    const linux = state.selected?.format.startsWith("linux-");
    const leads = result.network_lead_count ?? 0;
    const context = result.context_review_count ?? 0;
    const findings = result.finding_count - leads - context;
    const incomplete = c.excluded_records > 0 || result.rejected_record_count > 0 || unknown > 0;
    $("analysis-panel").dataset.review = findings || leads ? "flagged" : incomplete || context ? "context" : "idle";
    $("analysis-status").textContent = result.finding_count
      ? [findings ? `${findings} ${findings === 1 ? "finding needs" : "findings need"} review` : "",
         leads ? `${leads} network lead${leads === 1 ? "" : "s"}` : "",
         context ? `${context} ${context === 1 ? "item needs" : "items need"} source verification` : ""].filter(Boolean).join(" · ")
      : linux && !c.used_records ? "No rule matches · time-window checks unavailable"
      : !c.used_records ? "Insufficient evidence for checks" : incomplete ? "No rule matches · limited coverage" : "No rule matches";
    const details = [`${c.used_records} of ${c.input_records} parsed events in time windows`];
    if (result.flagged_record_count) details.push(`${result.flagged_record_count} records cited by findings`);
    if (result.network_lead_record_count) details.push(`${result.network_lead_record_count} additional records linked as network evidence`);
    if (result.windows_reviewed_count) details.push(`${result.windows_reviewed_count} checked by Windows evidence rules`);
    if (linux) details.push("Linux evidence rules ran on original records");
    if (unknown) details.push(`${unknown} without a normalized activity type`);
    if (c.excluded_records) details.push(`${c.excluded_records} excluded from time windows`);
    if (result.rejected_record_count) details.push(`${result.rejected_record_count} unreadable`);
    $("coverage-status").textContent = details.join(" · ") + ". No rule match does not establish safety.";
  }
}
async function loadAnalysisStatus() {
  const item = state.selected;
  if (!item) return;
  const sequence = ++state.analysisSequence;
  const result = await api(`/api/analysis/${item.id}`);
  if (sequence !== state.analysisSequence || state.selected?.id !== item.id) return;
  state.analysis = result; renderAnalysisStatus();
}
async function runChecks(item) {
  $("analysis-status").textContent = "Checking local activity…";
  try {
    state.analysis = await api(`/api/analysis/${item.id}`, {method: "POST", headers: {"X-Sentinel-Import": "1"}});
    renderAnalysisStatus(); state.offset = 0;
    $("record-kind").value = state.analysis.finding_count ? "findings" : "events";
    await loadRecords();
  } catch (error) { $("analysis-status").textContent = error.message; }
}
$("analyze-button").addEventListener("click", async () => {
  if (!state.selected || state.busy) return;
  setBusy(true);
  try { await runChecks(state.selected); } finally { setBusy(false); }
});
const activityLabels = {
  auth_failure: "Failed sign-in", auth_success: "Successful sign-in", account_created: "Account created",
  service_installed: "Service installed", service_state_change: "Service state changed",
  session_open: "Session opened", session_close: "Session closed", sudo_command: "Sudo command",
  privilege_assigned: "Privileges assigned", service_activity: "Service activity"
};
const windowsCodeHints = {
  1102: "Audit log cleared", 4624: "Successful sign-in", 4625: "Failed sign-in", 4648: "Explicit credentials used",
  4688: "Process started", 4698: "Scheduled task created", 4720: "Account created",
  4732: "Local group member added", 7045: "Service installed"
};

function hasMaintenanceNote(page, record) {
  return page.maintenance_note_events?.[record.upload_id]?.includes(record.event_id) ?? false;
}

function logBadges(badge, level, maintenance, blueTeam) {
  const badges = element("div", undefined, "log-badges");
  badges.append(element("span", badge, `review-badge badge-${level}`));
  if (maintenance) {
    const tag = element("span", "Maintenance note", "review-badge badge-context");
    tag.title = "A linked finding has a maintenance note. See Findings for the approval scope.";
    badges.append(tag);
  }
  if (blueTeam) {
    const tag = element("span", blueTeam.role === "target" ? "Blue Team sign-in target" : "Blue Team account",
      "review-badge badge-blue-team");
    tag.title = blueTeam.account;
    badges.append(tag);
  }
  return badges;
}

function logCard(record, {severity = null, checked = false, windowsChecked = false, maintenance = false, blueTeam = null} = {}) {
  const missingSource = record.platform === "windows" && (!record.channel || !record.provider);
  const needsContext = severity === "context" || (!record.event_type && !windowsChecked) || !record.timestamp_utc || !record.host;
  const level = severity === "lead" ? "lead" : severity === "critical" ? "critical" :
    severity === "warning" ? "flagged" : needsContext ? "context" : "neutral";
  const badge = severity === "lead" ? "Network lead" : severity === "critical" ? "Critical review" : severity === "warning" ? "Flagged for review" :
    needsContext ? "Needs context" : checked ? "No rule match" : "Observed";
  const hint = missingSource ? windowsCodeHints[record.windows_event_id] : null;
  const title = activityLabels[record.event_type] ?? (hint ? `Reported event ID ${record.windows_event_id} · ${hint}` :
    record.platform === "linux" && record.service ? `${record.service} event` : "Activity unclassified");
  const card = element("article", undefined, `record review-${level}`);
  const heading = element("div", undefined, "event-heading");
  heading.append(element("h4", title, "record-head"), logBadges(badge, level, maintenance, blueTeam));
  const time = record.timestamp_utc || (record.original_timestamp ? `${record.original_timestamp} (UTC unknown)` : "Time unknown");
  card.append(heading, element("p", `#${record.record_index} · ${time} · ${record.host || "Host unknown"}`, "event-meta"));
  const eventCode = record.windows_event_id && !hint ? `Windows event ID ${record.windows_event_id}` : record.service;
  const actors = [record.actor || record.target, record.source_ip, eventCode].filter(Boolean);
  if (actors.length) card.append(element("p", actors.join(" · "), "event-meta"));
  if (record.windows_event_id === 4688) {
    const raw = record.raw_record;
    const process = raw?.NewProcessName ?? raw?.EventData?.NewProcessName;
    const parent = raw?.ParentProcessName ?? raw?.EventData?.ParentProcessName;
    if (typeof process === "string" && process) {
      const processName = process.split(/[\\/]/).pop();
      const parentName = typeof parent === "string" ? parent.split(/[\\/]/).pop() : "";
      card.append(element("p", parentName ? `${parentName} → ${processName}` : processName, "event-meta"));
    }
  }
  if (missingSource) card.append(element("p", "Windows channel or provider missing. Verify the original source.", "event-meta"));
  const details = element("details");
  details.append(element("summary", "Original record"), element("pre", JSON.stringify(record, null, 2)));
  card.append(details);
  return card;
}
function featureCard(window) {
  const card = element("article", undefined, "record");
  card.append(element("div", `${window.host} · ${window.platform} · ${window.start_utc} to ${window.end_utc}`, "record-head"));
  card.append(element("p", `${window.evidence_count} records · ${window.vector.length} finite numeric features · ${window.feature_version}`));
  const details = element("details");
  details.append(element("summary", "Feature values, quality, and version fingerprint"), element("pre", JSON.stringify(window, null, 2)));
  card.append(details); return card;
}
function findingCard(entry, uploadId) {
  const finding = entry.finding;
  const level = entry.severity === "lead" ? "lead" : entry.severity === "critical" ? "critical" :
    entry.severity === "context" ? "context" : "flagged";
  const badge = level === "lead" ? "Network lead" : level === "critical" ? "Critical review" :
    level === "context" ? "Needs context" : "Flagged for review";
  const card = element("article", undefined, `record review-${level} finding-card`);
  const heading = element("div", undefined, "event-heading");
  heading.append(element("h4", entry.title ?? "Repeated failed sign-ins", "record-head"),
    logBadges(badge, level, Boolean(entry.maintenance_note)));
  card.append(heading, element("p", finding.explanation), element("p", `${finding.evidence_count} supporting events · Rule priority ${finding.triage_priority}/100`, "event-meta"));
  if (entry.source_metadata_complete === false) {
    card.append(element("p", "Source metadata incomplete. Confirm the events before acting.", "event-meta"));
  }
  if (!finding.timestamp_utc && entry.original_timestamp) {
    card.append(element("p", `Recorded time ${entry.original_timestamp} · UTC unknown`, "event-meta"));
  }
  const details = element("details");
  const body = element("div");
  details.append(element("summary", "Open supporting events"), body);
  const timeline = element("button", "View evidence in timeline", "secondary");
  timeline.type = "button";
  timeline.addEventListener("click", () => {
    state.mode = "timeline";
    state.filters = {upload_id: uploadId, finding_id: finding.finding_id};
    state.offset = 0;
    $("timeline-filters").reset();
    showSummary();
    loadRecords();
  });
  let loaded = false, evidenceOffset = 0;
  const controls = element("div", undefined, "evidence-controls");
  const previous = element("button", "Previous evidence", "secondary");
  const next = element("button", "Next evidence", "secondary");
  const page = element("span", "", "small muted");
  const evidence = element("div");
  async function evidencePage() {
    previous.disabled = true; next.disabled = true;
    try {
      const result = await api(`/api/findings/${finding.finding_id}/events?upload_id=${uploadId}&offset=${evidenceOffset}&limit=25`);
      evidence.replaceChildren(...result.items.map(record => logCard(record, {severity: entry.severity ?? "warning",
        maintenance: hasMaintenanceNote(result, record), blueTeam: result.blue_team_events?.[record.event_id]})));
      controls.hidden = result.total <= 25;
      page.textContent = `${evidenceOffset + 1}–${Math.min(evidenceOffset + 25, result.total)} of ${result.total}`;
      previous.disabled = evidenceOffset === 0; next.disabled = evidenceOffset + 25 >= result.total;
    } catch (error) { evidence.textContent = error.message; }
  }
  previous.addEventListener("click", () => { evidenceOffset = Math.max(0, evidenceOffset - 25); evidencePage(); });
  next.addEventListener("click", () => { evidenceOffset += 25; evidencePage(); });
  details.addEventListener("toggle", async () => {
    if (!details.open || loaded) return;
    loaded = true; body.textContent = "Loading evidence…";
    try {
      const context = await api(`/api/findings/${finding.finding_id}?upload_id=${uploadId}`);
      const technical = element("details");
      technical.append(element("summary", "Rule details and limits"), element("pre", JSON.stringify(context, null, 2)));
      appendCommandLinks(technical, context.manual_check_command_ids);
      body.replaceChildren(timeline, evidence, controls, technical);
      controls.append(previous, page, next); await evidencePage();
    } catch (error) { body.textContent = error.message; loaded = false; }
  });
  const saved = entry.maintenance_note;
  const maintenance = element("details");
  const form = element("form");
  const label = element("label", "Approval reference and scope");
  const note = element("textarea");
  note.value = saved?.note ?? "";
  note.maxLength = 1000;
  note.required = true;
  note.rows = 2;
  note.className = "maintenance-note";
  label.append(note);
  const save = element("button", "Save maintenance note", "secondary");
  save.type = "submit";
  const remove = element("button", "Remove note", "secondary");
  remove.type = "button";
  const status = element("p", "", "warnings");
  status.setAttribute("role", "status");
  const actions = element("div", undefined, "evidence-controls");
  actions.append(save);
  if (saved) actions.append(remove);
  form.append(label, actions, status);
  const notePath = `/api/findings/${finding.finding_id}/maintenance?upload_id=${uploadId}`;
  async function changeNote(method) {
    save.disabled = remove.disabled = true;
    status.textContent = "";
    try {
      await api(notePath, {
        method, headers: { "X-Sentinel-Import": "1", "Content-Type": "application/json" },
        body: method === "POST" ? JSON.stringify({ note: note.value }) : undefined
      });
      if (state.selected?.id === uploadId) await loadRecords();
    } catch (error) { status.textContent = error.message; }
    finally { save.disabled = remove.disabled = false; }
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (note.value.trim()) changeNote("POST");
    else status.textContent = "Enter an approval reference and scope.";
  });
  remove.addEventListener("click", () => changeNote("DELETE"));
  maintenance.append(element("summary", saved ? "Maintenance note recorded" : "Record approved maintenance"));
  if (saved) maintenance.append(element("p", `Updated by ${saved.username} · ${saved.updated_at}`, "event-meta"));
  maintenance.append(form);
  card.append(details, maintenance); return card;
}

async function loadOverview() {
  const item = state.selected;
  if (!item) return;
  const sequence = ++state.overviewSequence;
  const result = await api(`/api/uploads/${item.id}/overview`);
  if (sequence !== state.overviewSequence || state.selected?.id !== item.id) return;
  state.overview = result;
  renderAnalysisStatus();
  const body = $("overview-body");
  body.replaceChildren(element("p", `${result.host_count} known hosts · ${result.actor_count} known accounts · ${result.source_ip_count} known source IPs`));
  body.append(element("p", result.first_utc ? `Observed UTC span: ${result.first_utc} → ${result.last_utc}` : "No known UTC timestamps."));
  body.append(element("p", `Unknown fields: time ${result.unknown_time}; host ${result.missing_host}; account ${result.missing_actor}; source IP ${result.missing_source_ip}; activity ${result.unknown_activity}. Rejected input records: ${result.source.rejected_count}.`, "warnings"));
  const groups = element("div", undefined, "overview-groups");
  for (const [key, label, filter] of [["event_types", "Activity counts", "event_type"], ["hosts", "Top hosts", "host"], ["actors", "Top accounts", "actor"], ["source_ips", "Top source IPs", "source_ip"]]) {
    const group = element("div"); group.append(element("h4", label));
    const list = element("ul");
    for (const entry of result[key]) {
      const row = element("li"); const button = element("button", `${entry.value} · ${entry.count}`, "secondary");
      button.type = "button"; button.title = `View matching records in ${item.filename}`;
      button.addEventListener("click", () => {
        if (state.busy) return;
        state.mode = "timeline"; state.filters = {upload_id: item.id, [filter]: entry.value}; state.offset = 0;
        $("timeline-filters").reset();
        const ids = {event_type: "filter-type", host: "filter-host", actor: "filter-actor", source_ip: "filter-ip"};
        $(ids[filter]).value = entry.value; showSummary(); loadRecords();
      }); row.append(button); list.append(row);
    }
    if (!result[key].length) list.append(element("li", "No known values.", "small muted"));
    group.append(list); groups.append(group);
  }
  body.append(groups, element("p", result.limitations, "small muted"));
}

$("ask-form").addEventListener("submit", (event) => {
  event.preventDefault(); if (state.busy) return;
  const selected = $("ask-scope").value === "selected" ? state.selected : null;
  state.ask = {query: $("ask-query").value, upload_id: selected?.id ?? null, filename: selected?.filename ?? null};
  state.mode = "ask"; state.offset = 0; showSummary(); loadRecords();
});
api("/api/intents").then((help) => {
  for (const example of help.examples) {
    const button = element("button", example, "secondary"); button.type = "button";
    button.addEventListener("click", () => { $("ask-query").value = example; $("ask-query").focus(); });
    $("ask-examples").append(button);
  }
}).catch((error) => { $("ask-status").textContent = error.message; });

function appendCommandLinks(container, ids) {
  if (!ids?.length) return;
  const links = element("div", undefined, "command-actions");
  links.append(element("span", "Next manual checks (copy only):", "small muted"));
  for (const id of ids) {
    const button = element("button", `Review ${id}`, "secondary"); button.type = "button";
    button.addEventListener("click", () => openCommand(id)); links.append(button);
  }
  container.append(links);
}
function commandCard(entry) {
  const card = element("article", undefined, "record");
  card.append(element("h3", entry.title), element("p", `${entry.platform} · ${entry.category} · copy only`, "muted"), element("p", entry.purpose));
  const command = element("pre", entry.command); card.append(command);
  const actions = element("div", undefined, "command-actions"); const copy = element("button", "Copy command"); copy.type = "button";
  const status = element("span", "", "small muted"); status.setAttribute("role", "status");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(entry.command); status.textContent = "Copied. Review before manually running on the authorized target host."; }
    catch (_) { status.textContent = "Clipboard unavailable. Select and copy the command text above manually."; }
  }); actions.append(copy, status); card.append(actions);
  if (entry.output_format) card.append(element("p", `Logs import format: ${formatNames[entry.output_format] ?? entry.output_format}`, "small"));
  for (const [label, value] of [["Permissions", entry.permissions], ["Environment", entry.assumptions], ["Limits", entry.limitations], ["Review", `${entry.review.reviewer} · ${entry.review.date} · operational review pending`]]) card.append(element("p", `${label}: ${value}`, "small"));
  const link = element("a", "Command documentation (opens externally)"); link.href = entry.reference;
  link.target = "_blank"; link.rel = "noopener noreferrer"; card.append(link); return card;
}
function revealCatalog() { showTool("commands"); }
async function loadCatalog() {
  revealCatalog(); const sequence = ++state.commandSequence;
  const params = new URLSearchParams();
  for (const [id, key] of [["command-platform", "platform"], ["command-category", "category"], ["command-search", "q"]]) if ($(id).value) params.set(key, $(id).value);
  $("command-status").textContent = "Loading reference…"; $("commands").replaceChildren();
  try {
    const result = await api(`/api/commands?${params}`); if (sequence !== state.commandSequence) return;
    $("command-status").textContent = `${result.total} fixed command${result.total === 1 ? "" : "s"} · ${result.version}. No commands executed.`;
    for (const entry of result.items) $("commands").append(commandCard(entry));
    if (!result.total) $("commands").append(element("p", "No reference commands match these filters."));
  } catch (error) { if (sequence === state.commandSequence) $("command-status").textContent = error.message; }
}
async function openCommand(id) {
  revealCatalog(); $("command-filters").reset(); const sequence = ++state.commandSequence;
  $("commands").replaceChildren(); $("command-status").textContent = "Loading selected manual check…";
  try {
    const result = await api(`/api/commands/${encodeURIComponent(id)}`); if (sequence !== state.commandSequence) return;
    $("commands").append(commandCard(result.item)); $("command-status").textContent = `Selected manual check · ${result.version}. No commands executed.`;
    $("command-panel").scrollIntoView({block: "start", behavior: "smooth"});
  } catch (error) { if (sequence === state.commandSequence) $("command-status").textContent = error.message; }
}
$("catalog-button").addEventListener("click", () => loadCatalog());
$("log-collection-catalog").addEventListener("click", () => {
  $("command-filters").reset();
  $("command-category").value = "log_collection";
  loadCatalog();
});
$("command-filters").addEventListener("submit", (event) => { event.preventDefault(); loadCatalog(); });
$("close-catalog").addEventListener("click", () => { state.commandSequence++; openLibrary("logs"); });

function resetNetwork() {
  state.networkFilters = {}; state.networkFlowId = null; state.networkFindingId = null;
  $("network-filters").reset(); $("packet-status").value = ""; $("network-kind").value = "findings";
  $("network-summary-body").textContent = "Loading network header summary…";
}
async function loadSelectedContext() {
  if (state.selected?.format === "pcap") await loadNetworkSummary();
  else await Promise.all([loadAnalysisStatus(), loadOverview()]);
}
async function loadNetworkSummary() {
  const item = state.selected, sequence = ++state.networkSequence;
  const result = await api(`/api/network/${item.id}`);
  if (sequence !== state.networkSequence || state.selected?.id !== item.id) return;
  const body = $("network-summary-body"); body.replaceChildren();
  body.append(element("p", `${result.packet_count} captured records: ${result.decoded_packets} decoded TCP/UDP, ${result.skipped_packets} unsupported, ${result.malformed_packets} malformed headers. ${result.capture_truncated_packets} capture-truncated; ${result.unknown_timestamps} invalid timestamps.`));
  const stats = element("div", undefined, "network-statistics");
  for (const [value, label] of [[result.flow_count, "directional flows"], [result.protocol_counts.tcp || 0, "TCP packets"], [result.protocol_counts.udp || 0, "UDP packets"], [result.syn_without_ack_packets, "SYN without ACK packets"], [result.reset_packets, "RST packets"]]) {
    const card = element("div", undefined, "count"); card.append(element("strong", String(value)), element("span", label)); stats.append(card);
  }
  body.append(stats, element("p", result.first_decoded_utc ? `Decoded UTC span: ${result.first_decoded_utc} → ${result.last_decoded_utc}.` : "No decoded packets have valid timestamps."));
  if (result.review) {
    const review = result.review, counts = review.severity_counts;
    body.append(element("p", `${review.finding_count} traffic patterns to review · ${counts.critical || 0} high-priority · ${counts.warning || 0} warnings · ${counts.lead || 0} context leads. These are behavior indicators, not confirmed attacker activity.`, "request-context"));
    body.append(element("p", `${review.eligible_packets} timed decoded packets evaluated; ${review.collapsed_probe_records} repeated probe observations collapsed. Headers do not identify encrypted commands, authentication outcomes, or every attacker action.`, "small muted"));
    if (review.finding_count > review.returned_findings) body.append(element("p", `Finding limit: showing ${review.returned_findings} prioritized findings of ${review.finding_count}. Save/export the capture for additional investigation.`, "warnings"));
    const details = element("details");
    details.append(element("summary", "Detection policy and limitations"), element("pre", JSON.stringify(review, null, 2)));
    body.append(details);
  }
  body.append(element("p", `Decoded captured bytes: ${result.decoded_captured_bytes}; capture-declared original bytes: ${result.decoded_declared_original_bytes}. Timed decoded packet rate over the observed span: ${result.observed_timed_packets_per_second === null ? "unavailable (no positive span)" : `${result.observed_timed_packets_per_second.toFixed(3)} / second`}.`, "small muted"));
  const groups = element("div", undefined, "overview-groups");
  for (const [label, entries, makeLabel, filters] of [
    ["Top decoded peers", result.top_peers, (entry) => `${entry.address} · ${entry.packet_count} packets`, (entry) => ({peer: entry.address})],
    ["Top destination ports", result.top_destination_ports, (entry) => `${entry.protocol.toUpperCase()} ${entry.port} · ${entry.packet_count} packets`, (entry) => ({protocol: entry.protocol, destination_port: entry.port})]
  ]) {
    const group = element("div"); group.append(element("h4", label)); const list = element("ul");
    for (const entry of entries) {
      const row = element("li"); const button = element("button", makeLabel(entry), "secondary"); button.type = "button";
      button.addEventListener("click", () => { if (!state.busy) applyNetworkFilters(filters(entry)); });
      row.append(button); list.append(row);
    }
    if (!entries.length) list.append(element("li", "No decoded values.", "small muted"));
    group.append(list); groups.append(group);
  }
  body.append(groups);
  const coverage = Object.entries(result.exclusion_counts).map(([reason, count]) => `${reason}: ${count}`).join("; ");
  if (coverage) body.append(element("p", `Not decoded: ${coverage}`, "warnings"));
  body.append(element("p", "Flows are observed tuples, not verified connections. SYN counts include retransmissions. These counts do not establish compromise or safety.", "warnings"));
  const limits = element("details"); limits.append(element("summary", "Coverage, parser version, and limitations"), element("pre", JSON.stringify(result, null, 2))); body.append(limits);
  appendCommandLinks(body, ["windows-network", "linux-network"]);
}
function applyNetworkFilters(filters) {
  state.networkFilters = filters; state.networkFlowId = null; state.networkFindingId = null; state.offset = 0; $("network-kind").value = "flows";
  $("network-protocol").value = filters.protocol || ""; $("network-peer").value = filters.peer || ""; $("network-port").value = filters.destination_port ?? "";
  loadRecords();
}
function networkPath(id, kind) {
  const params = new URLSearchParams();
  const packets = kind === "packets";
  $("network-filters").hidden = kind !== "flows"; $("packet-status-control").hidden = !packets || Boolean(state.networkFindingId);
  if (kind === "findings") {
    $("network-context").textContent = "Versioned traffic-pattern findings · open supporting packets to inspect exact evidence. No match is not a safety verdict.";
    return `/api/network/${id}/findings?`;
  }
  if (packets) {
    if (state.networkFindingId) {
      $("network-context").textContent = "Supporting packet evidence for the selected traffic finding · original capture order.";
      return `/api/network/${id}/findings/${state.networkFindingId}/packets?`;
    }
    if (state.networkFlowId) params.set("flow_id", state.networkFlowId);
    if ($("packet-status").value) params.set("status", $("packet-status").value);
    $("network-context").textContent = `${state.networkFlowId ? `Packet evidence for flow ${state.networkFlowId}` : "All packet records in this capture"} · original file order. Header metadata only; source bytes are retained locally.`;
  } else {
    for (const [key, value] of Object.entries(state.networkFilters)) params.set(key, value);
    $("network-context").textContent = `Directional flows · highest observed packet counts first.${params.size ? ` Exact filters: ${params.toString()}` : " No flow filters."}`;
  }
  return `/api/network/${id}/${kind}?${params}&`;
}
function endpoint(ip, port) { return `${ip?.includes(":") ? `[${ip}]` : ip || "Unknown IP"}:${port ?? "?"}`; }
function networkBadge(card, tags) {
  const levels = {critical: 0, warning: 1, lead: 2};
  const severity = [...tags].sort((a,b) => levels[a.severity] - levels[b.severity])[0]?.severity;
  if (!severity) return;
  const style = severity === "warning" ? "flagged" : severity;
  card.classList.add(`review-${style}`);
  card.append(element("span", severity === "critical" ? "High-priority review" : severity === "warning" ? "Suspicious pattern" : "Context lead", `review-badge badge-${style}`));
}
function networkFindingCard(finding) {
  const card = element("article", undefined, "record");
  const compact = values => values.slice(0,8).join(", ") + (values.length > 8 ? ` (+${values.length-8} more)` : "");
  networkBadge(card, [finding]);
  card.append(element("h3", finding.title), element("p", finding.explanation),
    element("p", `${compact(finding.source_ips)} → ${compact(finding.destination_ips)} · ${finding.protocols.join(", ")} · destination ports ${compact(finding.destination_ports)}`, "event-meta"),
    element("p", `${finding.first_utc} → ${finding.last_utc} · ${finding.packet_count} supporting packets`, "small muted"),
    element("p", finding.next_check));
  const button = element("button", "Review supporting packets", "secondary"); button.type = "button";
  button.addEventListener("click", () => {
    if (state.busy) return;
    state.networkFindingId = finding.finding_id; state.networkFlowId = null;
    state.offset = 0; $("network-kind").value = "packets"; loadRecords();
  });
  const details = element("details");
  details.append(element("summary", "Measured values and evidence references"), element("pre", JSON.stringify(finding, null, 2)));
  card.append(button, details); return card;
}
function flowCard(flow) {
  const card = element("article", undefined, "record");
  networkBadge(card, flow.network_indicators || []);
  card.append(element("div", `${flow.protocol.toUpperCase()} · ${endpoint(flow.source_ip, flow.source_port)} → ${endpoint(flow.destination_ip, flow.destination_port)}`, "record-head"));
  card.append(element("p", `${flow.packet_count} packets · ${flow.captured_bytes} captured bytes · ${flow.syn_without_ack_packets} SYN without ACK · ${flow.reset_packets} RST · ${flow.packets_with_warnings} with warnings`));
  card.append(element("p", `${flow.first_utc || "Time unknown"} → ${flow.last_utc || "Time unknown"}${flow.vlan_ids.length ? ` · VLAN ${flow.vlan_ids.join(" / ")}` : ""}`, "muted"));
  const button = element("button", `Review ${flow.packet_count} packet records`, "secondary"); button.type = "button";
  button.addEventListener("click", () => { if (state.busy) return; state.networkFlowId = flow.flow_id; state.networkFindingId = null; state.offset = 0; $("network-kind").value = "packets"; $("packet-status").value = ""; loadRecords(); });
  const details = element("details"); details.append(element("summary", "Directional aggregate and evidence preview"), element("pre", JSON.stringify(flow, null, 2)));
  card.append(button, details); return card;
}
function packetCard(packet) {
  const card = element("article", undefined, "record");
  networkBadge(card, packet.network_indicators || []);
  card.append(element("div", `Packet #${packet.record_index} · ${packet.status} · ${packet.timestamp_utc || "Time unknown"}`, "record-head"));
  if (packet.source_ip || packet.destination_ip) card.append(element("p", `${packet.protocol?.toUpperCase() || `IP protocol ${packet.ip_protocol}`} · ${endpoint(packet.source_ip, packet.source_port)} → ${endpoint(packet.destination_ip, packet.destination_port)}`));
  card.append(element("p", `${packet.captured_length} captured bytes · ${packet.original_length} capture-declared original bytes · source offset ${packet.packet_data_offset}`));
  if (packet.reason) card.append(element("p", packet.reason, "warnings"));
  if (packet.warnings.length) card.append(element("p", packet.warnings.join("; "), "warnings"));
  const details = element("details"); details.append(element("summary", "Packet header fields and source-byte references"), element("pre", JSON.stringify(packet, null, 2))); card.append(details); return card;
}
$("network-filters").addEventListener("submit", (event) => {
  event.preventDefault(); if (state.busy) return;
  const filters = {};
  for (const [id, key] of [["network-protocol", "protocol"], ["network-peer", "peer"], ["network-port", "destination_port"]]) if ($(id).value) filters[key] = $(id).value;
  applyNetworkFilters(filters);
});
$("network-kind").addEventListener("change", () => { state.networkFlowId = null; state.networkFindingId = null; state.offset = 0; loadRecords(); });

const initialTool = new URLSearchParams(window.location.search).get("tool");
if (["network", "timeline", "commands"].includes(initialTool)) {
  document.querySelector(`[data-tool="${initialTool}"]`).click();
}

api("/health").then(async (health) => {
  if (!health.rehearsal_enabled) return;
  modelLabAvailable = true;
  try {
    const { mountModelReview } = await import("/static/rehearsal.js");
    modelReview = mountModelReview({ api, selectImport });
    modelReview.select(modelImport());
    $("model-review-panel").hidden = activeTool !== "logs";
  } catch (error) {
    $("model-review-panel").hidden = activeTool !== "logs";
    $("model-review-sample").disabled = true;
    $("model-review-status").textContent = error.message;
  }
}).catch((error) => { $("preview-error").textContent = error.message; });
$("packet-status").addEventListener("change", () => { state.offset = 0; loadRecords(); });
$("clear-network-filters").addEventListener("click", () => { state.networkFilters = {}; state.networkFlowId = null; state.networkFindingId = null; $("network-filters").reset(); $("packet-status").value = ""; state.offset = 0; loadRecords(); });
