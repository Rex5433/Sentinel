const byId = (id) => document.getElementById(id);
const activityNames = ["Normal activity", "Authentication burst", "Account change", "Service change"];
const lanes = {finding: "rehearsal-findings", coverage_notice: "rehearsal-coverage", confirmed_team_activity: "rehearsal-confirmed"};
const writeOptions = {method: "POST", headers: {"X-Sentinel-Import": "1"}};

export function mountModelReview({api, selectImport}) {
  const status = byId("model-review-status");
  const sample = byId("model-review-sample");
  const run = byId("model-review-run");
  const queue = byId("model-review-queue");
  let selectedId;
  let revision = 0;
  let eligible = false;
  let busy = false;
  let reviewedRevision = null;
  let confirmationBusy = false;

  function updateControls() {
    sample.disabled = busy || confirmationBusy;
    run.disabled = busy || confirmationBusy || !eligible;
  }

  function select(item) {
    const id = item?.id ?? null;
    if (id === selectedId) return;
    selectedId = id;
    const selectedRevision = ++revision;
    eligible = false;
    queue.hidden = true;
    status.textContent = id ? "Checking the selected import…" : "Load the sample or select a saved synthetic test export.";
    updateControls();
    if (!id) return;
    api("/api/rehearsal/imports").then(({items}) => {
      if (revision !== selectedRevision) return;
      eligible = items.some((entry) => entry.id === id);
      if (reviewedRevision !== selectedRevision) {
        status.textContent = eligible ? "Ready to review the selected import." : "This import is outside the synthetic model test set.";
      }
      updateControls();
    }).catch((error) => {
      if (revision === selectedRevision && reviewedRevision !== selectedRevision) status.textContent = error.message;
    });
  }

  function node(tag, text) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    return element;
  }


  function render(result, captureId) {
    const data = result.queue;
    status.textContent = `${data.active_items} active items · ${data.coverage_notices} coverage notices · ${data.confirmed_items} confirmed · analysis ${result.analysis_ms} ms`;
    for (const [kind, id] of Object.entries(lanes)) {
      const cards = data.items.filter((item) => item.kind === kind);
      if (kind === "finding") {
        cards.sort((first, second) => Number(first.windows[0].priority === "lower") - Number(second.windows[0].priority === "lower"));
      }
      byId(id).replaceChildren(...(cards.length ? cards.map((item) => card(item, captureId)) : [node("p", "No items.")]));
    }
    queue.hidden = false;
  }

  function card(item, captureId) {
    const cardRevision = revision;
    const first = item.windows[0];
    const title = item.kind === "coverage_notice" ? "Short log history" : activityNames[first.activity_class] ?? "Activity unassessed";
    const block = node("article");
    const [level, label] = item.kind === "finding" ? ["flagged", "Flagged for review"] :
      item.kind === "coverage_notice" ? ["context", "Needs context"] : ["confirmed", "Confirmed team activity"];
    block.className = `record review-${level}`;
    const heading = node("div");
    heading.className = "event-heading";
    const badge = node("span", label);
    badge.className = `review-badge badge-${level}`;
    heading.append(node("h4", title), badge);
    block.append(heading, node("p", `${item.host ?? "Host unknown"} · ${item.platform} · ${first.start_utc ?? "Time unknown"}`));
    if (first.priority === "lower") block.append(node("p", "Lower priority · CNN flag needs corroboration"));
    if (item.confirmation) block.append(node("p", `Confirmed by ${item.confirmation.reviewer} · ${item.confirmation.reference}`));
    for (const interval of item.windows) {
      const message = interval.gap_end_utc ? `Coverage gap through ${interval.gap_end_utc}` : interval.reasons.join(", ");
      block.append(node("p", `${interval.start_utc ?? "Time unknown"} · ${message || "Correlated authentication evidence"}`));
    }

    const details = node("details");
    const evidence = node("div");
    details.append(node("summary", "Review original evidence"), evidence);
    block.append(details);
    let loaded = false;
    let offset = 0;
    async function loadEvidence() {
      const data = await api(`/api/rehearsal/${captureId}/items/${item.item_id}/events?offset=${offset}`);
      const original = (record) => node("pre", typeof record.raw_record === "string" ? record.raw_record : JSON.stringify(record.raw_record, null, 2));
      const records = data.items.map(original);
      evidence.replaceChildren(node("p", `Showing ${offset + (records.length ? 1 : 0)}–${offset + records.length} of ${data.total} records`), ...records);
      const more = node("button", "Next evidence records");
      more.type = "button";
      more.disabled = offset + records.length >= data.total;
      more.addEventListener("click", async () => {
        more.disabled = true;
        offset += 25;
        try { await loadEvidence(); } catch (error) { offset -= 25; evidence.append(node("p", error.message)); more.disabled = false; }
      });
      evidence.append(more);
      if (item.kind === "finding" && [2, 3].includes(first.activity_class) && data.action_records.length) {
        evidence.append(node("h4", "Records covered by this confirmation"), ...data.action_records.map(original));
        const form = node("form");
        const label = node("label", "Team change reference");
        const reference = node("input");
        reference.maxLength = 256;
        reference.required = true;
        label.append(reference);
        const confirm = node("button", "Confirm this reviewed team action");
        confirm.type = "submit";
        form.append(label, confirm);
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          if (busy || confirmationBusy) return;
          confirmationBusy = true;
          updateControls();
          confirm.disabled = true;
          try {
            const result = await api(`/api/rehearsal/${captureId}/confirmations`, {
              method: "POST", headers: {"Content-Type": "application/json", "X-Sentinel-Import": "1"},
              body: JSON.stringify({item_id: item.item_id, reference: reference.value})
            });
            if (revision === cardRevision) render(result, captureId);
          } catch (error) { evidence.append(node("p", error.message)); }
          finally { confirmationBusy = false; confirm.disabled = false; updateControls(); }
        });
        evidence.append(form);
      }
    }
    details.addEventListener("toggle", async () => {
      if (!details.open || loaded) return;
      loaded = true;
      evidence.textContent = "Loading evidence…";
      try { await loadEvidence(); } catch (error) { evidence.textContent = error.message; loaded = false; }
    });
    return block;
  }

  async function open(captureId, selectedRevision) {
    reviewedRevision = selectedRevision;
    queue.hidden = true;
    status.textContent = "Preparing review queue…";
    try {
      await api(`/api/rehearsal/${captureId}/analysis`, writeOptions);
      const result = await api(`/api/rehearsal/${captureId}/queue`);
      if (revision === selectedRevision) render(result, captureId);
    } catch (error) {
      if (revision === selectedRevision) status.textContent = error.message;
    }
  }

  async function review(loadSample) {
    if (busy || confirmationBusy || (!loadSample && !eligible)) return;
    busy = true;
    updateControls();
    try {
      if (loadSample) {
        status.textContent = "Loading the synthetic sample…";
        const item = await api("/api/rehearsal/sample", writeOptions);
        await selectImport(item);
        if (selectedId !== item.id) return;
        eligible = true;
      }
      await open(selectedId, revision);
    } catch (error) {
      status.textContent = error.message;
    } finally {
      busy = false;
      updateControls();
    }
  }

  sample.addEventListener("click", () => review(true));
  run.addEventListener("click", () => review(false));
  byId("model-review-panel").hidden = false;
  return {select};
}

