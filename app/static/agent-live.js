"use strict";
(function () {
const $ = id => document.getElementById(id);
const {element, request, validId, timelineUrl, eventCard, findingCard} = window.SentinelAgentView;
const panel = $("agent-feed");
const host = $("agent-feed-host");
const initialAgent = new URLSearchParams(window.location.search).get("agent");
let preferred = validId(initialAgent) ? initialAgent : "";
let hostRequest = 0;
let feedRequest = 0;
let loadingFeed = false;
let rendered;

function status(text, error = false) {
  $("agent-feed-status").textContent = text;
  $("agent-feed-status").classList.toggle("error", error);
}

async function refreshFeed() {
  const id = host.value;
  const seq = ++feedRequest;
  if (!validId(id)) {
    status("Select a host to see collected events.");
    $("agent-feed-content").hidden = true;
    loadingFeed = false;
    return;
  }
  loadingFeed = true;
  try {
    const result = await request(`/api/agents/${encodeURIComponent(id)}/live`);
    if (seq !== feedRequest || !panel.open) return;
    const review = result.review;
    const count = review.events.length;
    status(`${count} recent ${count === 1 ? "event" : "events"} available`);
    $("agent-feed-detail").href = `/agents?${new URLSearchParams({agent: id})}`;
    $("agent-feed-timeline").href = timelineUrl(id);
    $("agent-feed-content").hidden = false;
    const signature = JSON.stringify([id, review]);
    if (signature === rendered) return;
    rendered = signature;
    const events = review.events.slice(-30).reverse().map(event => eventCard(event, review));
    const evidence = new Map(review.events.map(row => [row.event_id, row]));
    const findings = review.findings.slice(0, 15).map(entry => findingCard(entry, evidence, review));
    $("agent-feed-events").replaceChildren(...(events.length ? events : [element("p", "No events collected yet.", "muted")]));
    $("agent-feed-findings").replaceChildren(...(findings.length ? findings : [element("p", "No recent findings.", "muted")]));
  } catch (error) {
    if (seq === feedRequest && panel.open) status(error.message, true);
  } finally {
    if (seq === feedRequest) loadingFeed = false;
  }
}

async function refreshHosts() {
  const seq = ++hostRequest;
  try {
    const result = await request("/api/agents");
    if (seq !== hostRequest || !panel.open) return;
    const valid = result.items.filter(entry => validId(entry.id));
    host.replaceChildren(new Option("Choose a host", ""), ...valid.map(entry => new Option(entry.name, entry.id)));
    const selection = valid.find(entry => entry.id === preferred) ?? valid[0];
    host.value = selection?.id ?? "";
    if (!valid.length) {
      status("Add a host on SIEM Agents to open its feed here.");
      $("agent-feed-content").hidden = true;
      return;
    }
    preferred = host.value;
    await refreshFeed();
  } catch (error) {
    if (seq === hostRequest && panel.open) status(error.message, true);
  }
}

host.addEventListener("change", () => {
  preferred = host.value;
  $("agent-feed-content").hidden = true;
  refreshFeed();
});
$("agent-feed-refresh").addEventListener("click", refreshHosts);
panel.addEventListener("toggle", () => {
  if (panel.open) refreshHosts();
});
if (preferred) {
  panel.open = true;
  if (window.location.hash === "#agent-feed") requestAnimationFrame(() => panel.scrollIntoView());
}
setInterval(() => {
  if (panel.open && !document.hidden && host.value && !loadingFeed) refreshFeed();
}, 10000);
})();
