"use strict";
(function (global) {
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function request(path, {method = "GET", data, timeout = 10000} = {}) {
  const headers = {};
  if (method !== "GET") headers["X-Sentinel-Import"] = "1";
  if (data !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method, headers, cache: "no-store", signal: AbortSignal.timeout(timeout),
    body: data === undefined ? undefined : JSON.stringify(data)
  });
  if (response.status === 401) window.location.replace("/login");
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const error = payload?.detail;
    const detail = typeof error === "string" ? error.slice(0, 500) : typeof error?.message === "string" ? error.message.slice(0, 500) : "";
    throw new Error(detail || `Sentinel returned HTTP ${response.status}.`);
  }
  return response.status === 204 ? null : response.json();
}

function validId(value) {
  return typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
}

function timelineUrl(agentId, collector) {
  const params = new URLSearchParams({tool: "timeline", source_kind: "agents", agent_id: agentId});
  if (collector) params.set("collector", collector);
  return `/?${params}`;
}

function eventCard(event, review = {}) {
  const id = event.event_id;
  const card = global.SentinelLogView.logCard(event, {
    severity: event.agent_severity ?? review.flagged?.[id], checked: true,
    windowsChecked: (review.windows_reviewed_event_ids ?? []).includes(id),
    maintenance: (review.maintenance_note_event_ids ?? []).includes(id),
    blueTeam: review.blue_team_events?.[id], userAccount: review.user_account_events?.[id],
    showMessage: "collapsed"
  });
  const source = event.collector ? `Managed SSH · ${event.collector}` : "Managed SSH";
  card.append(element("p", source, "small muted"));
  return card;
}

function findingCard(entry, supporting = new Map(), review = {}) {
  const finding = entry.finding ?? entry;
  const level = {critical: "critical", warning: "flagged", lead: "lead", context: "context"}[entry.severity] || "neutral";
  const card = element("article", undefined, `record review-${level}`);
  const heading = element("div", undefined, "event-heading");
  const label = {critical: "Critical review", flagged: "Flagged for review", lead: "Lead", context: "Verify activity"}[level] || "Finding";
  heading.append(element("h4", entry.title || finding.title || "Security finding", "record-head"),
    global.SentinelLogView.logBadges(label, level, entry.maintenance_note));
  card.append(heading);
  if (finding.explanation) card.append(element("p", finding.explanation));
  if (finding.timestamp_utc) card.append(element("p", finding.timestamp_utc, "small muted"));
  const records = (finding.evidence_event_ids ?? []).map(id => supporting.get(id)).filter(Boolean).slice(0, 5);
  const hasEvidence = (finding.evidence_event_ids ?? []).length > 0;
  if (hasEvidence && validId(review.id) && finding.finding_id) {
    const details = element("details");
    const content = element("div");
    details.append(element("summary", "Supporting records"), content);
    details.addEventListener("toggle", async () => {
      if (!details.open || content.childNodes.length) return;
      content.textContent = "Loading evidence…";
      try {
        const path = `/api/agents/${review.id}/findings/${encodeURIComponent(finding.finding_id)}/evidence`;
        const evidence = await request(path);
        content.replaceChildren(element("p", `Showing ${evidence.events.length} of ${evidence.total_cited} cited records.`, "small muted"),
          ...evidence.events.map(event => eventCard(event, evidence)));
      } catch (error) {
        content.replaceChildren(element("p", error.message, "small muted"), ...records.map(event => eventCard(event, review)));
      }
    });
    card.append(details);
  } else if (records.length) {
    const details = element("details");
    details.append(element("summary", `Supporting records (${records.length} shown)`));
    details.addEventListener("toggle", () => {
      if (details.open && details.children.length === 1) details.append(...records.map(record => eventCard(record, review)));
    });
    card.append(details);
  }
  return card;
}

global.SentinelAgentView = Object.freeze({element, request, validId, timelineUrl, eventCard, findingCard});
})(window);
