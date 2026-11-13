"use strict";
(function (global) {
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
const activityLabels = {
  auth_failure: "Failed sign-in", auth_success: "Successful sign-in", account_created: "Account created",
  service_installed: "Service installed", service_state_change: "Service state changed",
  session_open: "Session opened", session_close: "Session closed", sudo_command: "Sudo command",
  privilege_assigned: "Privileges assigned", service_activity: "Service activity",
  sudo_session_open: "Sudo session opened", ssh_disconnected: "SSH disconnected", ssh_connection: "SSH connection received",
  ssh_invalid_account: "SSH invalid account", ssh_pam_failure: "SSH authentication error",
  linux_audit: "Linux audit record", kernel_activity: "Kernel activity", industrial_protocol_activity: "MQTT / Modbus activity",
  account_management: "Account management activity", scheduled_job_activity: "Scheduled job activity",
  explicit_credentials: "Explicit credentials used", process_started: "Process started", account_changed: "Account changed",
  system_access_granted: "System access granted", system_access_removed: "System access removed",
  audit_policy_changed: "Audit policy changed", group_member_removed: "Group member removed",
  credential_validation: "Credential validation", group_membership_read: "Local group membership queried",
  network_connection_allowed: "Network connection allowed", network_connection_blocked: "Network connection blocked",
  network_packet_allowed: "Firewall allowed a packet", network_packet_blocked: "Firewall blocked a packet",
  network_port_bound: "Application bound to a local port", firewall_observation: "Firewall observed traffic",
  event_logging_started: "Event logging started", event_logging_stopped: "Event logging stopped",
  audit_log_cleared: "Security audit log cleared", defender_detection: "Defender threat detected",
  defender_action: "Defender protection action reported", defender_action_failed: "Defender protection action failed",
  defender_protection_disabled: "Defender real-time protection disabled", defender_settings_changed: "Defender settings changed",
  tls_handshake_failed: "TLS handshake failed", service_start_failed: "Service failed to start",
  service_stopped_unexpectedly: "Service stopped unexpectedly", shutdown_requested: "Shutdown requested",
  remote_management_listening: "Remote management listener started", sign_in_notification_failed: "Sign-in notification failed",
  performance_counter_failed: "Performance counter failed", service_startup_changed: "Service startup type changed",
  task_started: "Scheduled task started", task_completed: "Scheduled task completed", task_triggered: "Scheduled task triggered",
  task_process_started: "Scheduled task process launched", task_registered: "Scheduled task registered",
  task_updated: "Scheduled task updated", task_deleted: "Scheduled task deleted", task_disabled: "Scheduled task disabled",
  task_action_started: "Scheduled task action started", task_action_completed: "Scheduled task action ended",
  dpapi_key_found: "Windows found a DPAPI credential key", volume_mount_requested: "Volume mount requested",
  volume_mounted: "Volume mounted", folder_check_failed: "Known folder check failed",
  appx_registration_checked: "Windows app registration checked", powershell_starting: "PowerShell console starting",
  powershell_ready: "PowerShell console ready", powershell_ipc_started: "PowerShell local IPC started",
  powershell_module_logged: "PowerShell module activity logged", powershell_script_logged: "PowerShell script recorded",
  bits_job_list_loaded: "BITS loaded its job list", device_manager_started: "Device setup service started",
  device_manager_stopped: "Device setup service stopped", device_serviced: "Device setup tasks ran",
  device_ready: "Device container ready", device_configured: "Device configured", device_started: "Device started",
  device_removed: "Device entry removed", remote_ntlm_authentication: "Remote NTLM authentication observed",
  ntfs_latency_report: "NTFS I/O latency summary", default_printer_changed: "Default printer changed"
};
const routine = new Set(["task_started", "task_completed", "task_triggered", "task_process_started", "task_action_started",
  "dpapi_key_found", "volume_mount_requested", "volume_mounted", "appx_registration_checked", "powershell_starting",
  "powershell_ready", "powershell_ipc_started", "bits_job_list_loaded", "device_manager_started", "device_manager_stopped",
  "device_serviced", "device_ready", "device_configured", "device_started", "device_removed", "ntfs_latency_report",
  "default_printer_changed", "event_logging_started", "industrial_protocol_activity"]);
const configuration = new Set(["service_startup_changed", "audit_policy_changed", "defender_settings_changed",
  "service_installed", "account_changed", "account_created", "group_member_removed", "system_access_granted",
  "system_access_removed", "task_registered", "task_updated", "task_deleted", "task_disabled"]);
const operationalErrors = new Set(["folder_check_failed", "tls_handshake_failed", "service_start_failed",
  "service_stopped_unexpectedly", "sign_in_notification_failed", "performance_counter_failed"]);

function eventAssessment(record, severity, missingSource) {
  const kind = record.event_type;
  if (severity === "critical") return ["Critical review", "critical", "A high-priority review pattern matched. Check the supporting evidence."];
  if (severity === "warning") return ["Flagged for review", "flagged", "A review pattern matched. Verify the evidence and authorization."];
  if (severity === "lead") return ["Network lead", "lead", "Investigate the observed network pattern."];
  if (configuration.has(kind)) return ["Configuration review", "context", "Compare this change with expected settings and authorized maintenance."];
  if (severity === "context") return ["Verify activity", "context", "A linked finding explains what to verify before judging authorization or outcome."];
  if (missingSource || !record.timestamp_utc || !record.host) return ["Incomplete record", "context", "The source, absolute time, or reporting host is incomplete."];
  if (!kind) return ["Unmapped activity", "context", "Review the provider and original message. The event has no supported interpretation yet."];
  if (kind === "task_action_completed") {
    const result = record.raw_record?.EventData?.ResultCode ?? record.raw_record?.ResultCode;
    return String(result).trim() === "0" || /^0x0+$/i.test(String(result))
      ? ["Routine pattern", "neutral", "Task Scheduler reported an action exit code of zero. Verify the task and action are expected."]
      : ["Check task result", "context", "Review the recorded task action and its result code."];
  }
  if (kind === "remote_ntlm_authentication") return ["Verify remote sign-in", "context", "Check whether the NTLM client and account are expected for this host."];
  if (routine.has(kind)) return ["Routine pattern", "neutral", "This record matches a common operating-system or scheduled-task event. Check authorization if unexpected."];
  if (operationalErrors.has(kind)) return ["Operational error", "context", "The source reported an error. Check related service or application records."];
  if (kind.startsWith("network_") || kind === "firewall_observation") return ["Network activity", "neutral", "Check the application, peer, and port against expected traffic."];
  if (kind === "auth_failure" || kind === "ssh_invalid_account" || kind === "ssh_pam_failure")
    return ["Sign-in failed", "neutral", "A failed sign-in alone can be a mistake. Look for repeated attempts or a linked success."];
  if (kind === "auth_success" || kind === "credential_validation" || kind === "explicit_credentials")
    return ["Sign-in activity", "neutral", "Check whether the recorded account and source are expected."];
  return ["Activity recorded", "neutral", "Review the named activity and its original record if unexpected."];
}
const taskCodeHints = {
  100: "Scheduled task started", 102: "Scheduled task completed", 106: "Scheduled task registered",
  140: "Scheduled task updated", 141: "Scheduled task deleted", 142: "Scheduled task disabled",
  200: "Scheduled action started", 201: "Scheduled action completed"
};
const windowsCodeHints = {
  104: "Windows event log cleared", 1102: "Audit log cleared", 4624: "Successful sign-in", 4625: "Failed sign-in", 4648: "Explicit credentials used",
  4657: "Registry value changed", 4688: "Process started", 4697: "Service installed", 4698: "Scheduled task created",
  4699: "Scheduled task deleted", 4700: "Scheduled task enabled", 4701: "Scheduled task disabled",
  4702: "Scheduled task updated", 4719: "Audit policy changed", 4720: "Account created",
  4732: "Local group member added", 7040: "Service startup type changed", 7045: "Service installed"
};

function hasMaintenanceNote(page, record) {
  return page.maintenance_note_events?.[record.upload_id]?.includes(record.event_id) ?? false;
}

function logBadges(badge, level, maintenance, blueTeam, userAccount) {
  const badges = element("div", undefined, "log-badges");
  const status = element("span", badge, `review-badge badge-${level}`);
  status.title = badge === "Needs context"
    ? "Missing source/time/host information, unsupported activity, or a context-only rule prevents a complete assessment."
    : badge === "No rule match" ? "No current rule matched this record. This is not a safety verdict."
    : badge === "Flagged for review" || badge === "Critical review" ? "A review pattern matched. Verify evidence and authorization; this is not a confirmed attacker identity."
    : badge === "Network lead" ? "A network-related pattern needs investigation. It is not a confirmed malicious connection."
    : badge === "Failed sign-in" ? "Authentication failed; this record alone may be a mistake or an unauthorized attempt." : "";
  badges.append(status);
  if (maintenance) {
    const tag = element("span", "Maintenance note", "review-badge badge-context");
    tag.title = "A linked finding has a maintenance note. See Findings for the approval scope.";
    badges.append(tag);
  }
  if (blueTeam) {
    const tag = element("span", blueTeam.role === "target" ? "Blue Team sign-in target" : "Blue Team account",
      "review-badge badge-blue-team");
    tag.title = `${blueTeam.account} — rostered account, not proof of who used it or whether this action was authorized.`;
    badges.append(tag);
  }
  if (userAccount) {
    const tag = element("span", userAccount.role === "target" ? "Known user sign-in target" : "Known user account",
      "review-badge badge-known-user");
    tag.title = `${userAccount.account} · Account recorded in the event. Verify the operator and authorization.`;
    badges.append(tag);
  }
  return badges;
}

function logCard(record, {severity = null, windowsChecked = false, maintenance = false,
                         blueTeam = null, userAccount = null, showMessage = false} = {}) {
  const missingSource = record.platform === "windows" && (!record.channel || !record.provider);
  const [badge, level, interpretation] = eventAssessment(record, severity, missingSource);
  const taskChannel = record.channel?.toLowerCase() === "microsoft-windows-taskscheduler/operational";
  const hint = (missingSource || windowsChecked) ? (taskChannel ? taskCodeHints : windowsCodeHints)[record.windows_event_id] : null;
  const title = activityLabels[record.event_type] ?? (hint ? (missingSource ? `Reported event ID ${record.windows_event_id} · ${hint}` : hint) :
    record.platform === "linux" ? (record.service ? `${record.service} event` : "Linux log record") :
      [record.provider || record.channel || "Windows", record.windows_event_id != null ? `event ${record.windows_event_id}` : "log record"].join(" · "));
  const card = element("article", undefined, `record review-${level}`);
  const heading = element("div", undefined, "event-heading");
  const badges = logBadges(badge, level, maintenance, blueTeam, userAccount);
  badges.firstElementChild.title = interpretation;
  heading.append(element("h4", title, "record-head"), badges);
  const time = record.timestamp_utc || (record.original_timestamp ? `${record.original_timestamp} (UTC unknown)` : "Time unknown");
  card.append(heading, element("p", `#${record.record_index} · ${time} · ${record.host || "Host unknown"}`, "event-meta"));
  const eventCode = record.windows_event_id && !(missingSource && hint) ? `Windows event ID ${record.windows_event_id}` : record.service;
  const actors = [record.actor || record.target, record.source_ip, record.channel, eventCode].filter(Boolean);
  if (actors.length) card.append(element("p", actors.join(" · "), "event-meta"));
  const fields = record.raw_record?.EventData;
  if (fields && record.event_type?.startsWith("task_")) {
    const details = [fields.TaskName, fields.ActionName ?? fields.Path,
      fields.ResultCode != null ? `Result ${fields.ResultCode}` : null].filter(value => typeof value === "string" && value);
    if (details.length) card.append(element("p", details.join(" · "), "event-meta"));
  }
  if (fields && record.event_type === "service_startup_changed" && typeof fields.param1 === "string") {
    const transition = [fields.param2, fields.param3].filter(value => typeof value === "string").join(" → ");
    card.append(element("p", [fields.param1, transition].filter(Boolean).join(" · "), "event-meta"));
  }
  if (fields && record.event_type?.startsWith("network_") && typeof fields.Application === "string") {
    const application = fields.Application.split(/[\\/]/).pop();
    const endpoint = (address, port) => typeof address === "string" && port != null ? `[${address}]:${port}` : "";
    const from = endpoint(fields.SourceAddress, fields.SourcePort);
    const to = endpoint(fields.DestAddress, fields.DestPort);
    card.append(element("p", [application, [from, to].filter(Boolean).join(" → ")].filter(Boolean).join(" · "), "event-meta"));
  }
  if (fields && record.event_type === "remote_ntlm_authentication" && typeof fields.Username === "string") {
    card.append(element("p", fields.Username, "event-meta"));
  }
  if (showMessage && record.message) {
    if (showMessage === "collapsed") {
      const message = element("details");
      message.append(element("summary", "Event message"), element("p", record.message));
      card.append(message);
    } else card.append(element("p", record.message));
  }
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

function sshObservation(record) {
  const label = {
    reachable: "Sentinel SSH read succeeded",
    failed: "Sentinel SSH read failed",
  }[record.ssh_status];
  if (!label) return "No recent Sentinel SSH result";
  return record.ssh_observed_at ? `${label} · ${record.ssh_observed_at}` : label;
}

function wazuhEventCard(record, {timelineLink = false} = {}) {
  const disconnected = record.event_type === "agent_disconnected";
  const recovered = record.event_type === "agent_recovered";
  const health = disconnected || recovered;
  const level = record.rule_level;
  const severity = level >= 15 ? "Critical" : level >= 10 ? "High" : level >= 7 ? "Medium" : "Low";
  const style = disconnected ? "flagged" : !health && level >= 15 ? "critical" : !health && level >= 10 ? "flagged" : "neutral";
  const title = disconnected ? "Agent disconnected" : recovered ? "Agent recovered" :
    record.rule_description || "Wazuh rule matched";
  const card = element("article", undefined, `record review-${style}`);
  card.dataset.eventId = record.id;
  const heading = element("div", undefined, "event-heading");
  heading.append(element("h4", title, "record-head"), logBadges(health ? "Wazuh agent health" :
    Number.isInteger(level) ? `Wazuh · ${severity}` : "Wazuh alert", style));
  const endpoint = record.raw_event?.agentless?.host || record.raw_event?.predecoder?.hostname ||
    record.agent_name || record.raw_event?.manager?.name || (record.agent_id ? `Agent ${record.agent_id}` : "Unknown source");
  const details = [record.timestamp || "Time unknown", endpoint,
    record.agent_name && record.agent_id ? `Agent ${record.agent_id}` : null, record.agent_ip || record.ip];
  card.append(heading, element("p", details.filter(Boolean).join(" · "), "event-meta"));
  if (!health) {
    const rule = [record.rule_id ? `Rule ${record.rule_id}` : null,
      Number.isInteger(record.rule_level) ? `Wazuh level ${record.rule_level}` : null,
      ...(Array.isArray(record.rule_groups) ? record.rule_groups : [])];
    if (rule.some(Boolean)) card.append(element("p", rule.filter(Boolean).join(" · "), "event-meta"));
  }
  card.append(element("p", sshObservation(record), "small muted"));
  if (typeof record.ssh_host === "string" && record.ssh_host && record.ssh_host.length <= 255) {
    const link = element("a", "View Sentinel events for this host");
    link.href = `/?${new URLSearchParams({tool: "timeline", source_kind: "sentinel", host: record.ssh_host})}`;
    const row = element("p");
    row.append(link);
    card.append(row);
  }
  if (timelineLink && /^[a-f0-9]{64}$/.test(record.id)) {
    const link = element("a", "Open in Timeline");
    link.href = `/?tool=timeline&wazuh_event=${record.id}`;
    card.append(link);
  }
  const original = element("details");
  original.append(element("summary", health ? "Original observation" : "Original alert"),
    element("pre", JSON.stringify(record.raw_event ?? record, null, 2)));
  card.append(original);
  return card;
}

function nmapCard(record) {
  const card = element("article", undefined, "record review-context");
  const heading = element("div", undefined, "event-heading");
  heading.append(element("h4", "TCP port changes observed", "record-head"), logBadges("Nmap observation", "context"));
  const labels = {new_open: "Newly open", now_closed: "Now closed", now_filtered: "Now filtered"};
  card.append(heading, element("p", [record.target, record.host, record.timestamp].filter(Boolean).join(" · "), "event-meta"));
  for (const [key, ports] of Object.entries(record.changes ?? {})) {
    if (labels[key] && ports.length) card.append(element("p", `${labels[key]} · ${ports.join(", ")}`, "small"));
  }
  return card;
}

global.SentinelLogView = Object.freeze({logCard, logBadges, hasMaintenanceNote, wazuhEventCard, sshObservation, nmapCard});
})(window);
