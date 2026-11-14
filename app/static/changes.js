"use strict";
const $ = (id) => document.getElementById(id);
const changesState = {snapshots: [], pair: null, offset: 0, sequence: 0, busy: false};
function node(tag, text, className) { const result = document.createElement(tag); if (text !== undefined) result.textContent = text; if (className) result.className = className; return result; }
async function request(path, options={}) {
  const response = await fetch(path, {cache: "no-store", ...options});
  if (response.status === 401) { window.location.replace("/login"); throw new Error("Sign in again to view evidence."); }
  if (!response.ok) { let message = `Request failed (${response.status}).`; try { const value = await response.json(); if (typeof value.detail === "string") message = value.detail; } catch (_) {} throw new Error(message); }
  return response.status === 204 ? null : response.json();
}
function invalidate() { changesState.sequence++; changesState.pair = null; changesState.offset=0; $("baseline-trust").checked=false; $("change-reports").hidden=true; $("change-records").replaceChildren(); $("change-summary").replaceChildren(); $("change-page").textContent=""; $("change-previous").disabled=true; $("change-next").disabled=true; $("change-status").textContent="Choose a baseline and current snapshot, then compare."; }
function busy(value) { changesState.busy=value; for (const id of ["snapshot-import","snapshot-file","baseline-select","current-select","compare-button","refresh-snapshots","delete-snapshot"]) $(id).disabled=value; }
async function loadSnapshots(currentId=null) {
  const result = await request("/api/snapshots"); changesState.snapshots=result.items;
  const previousBaseline=$("baseline-select").value, previousCurrent=currentId || $("current-select").value;
  for (const id of ["baseline-select","current-select"]) {
    $(id).replaceChildren(node("option", "Choose snapshot…")); $(id).options[0].value="";
    for (const entry of result.items) { const option=node("option", `${entry.source.filename} · ${entry.host.name} · ${entry.ended_at_utc}`); option.value=entry.source.id; $(id).append(option); }
  }
  $("baseline-select").value=previousBaseline; $("current-select").value=previousCurrent;
  $("pair-info").textContent=`${result.total} retained snapshots. Shared import limit: 25; retention: 7 days. Deleting/expiry removes comparison sources.`;
}
function pairParams() { return new URLSearchParams(changesState.pair); }
async function loadChanges() {
  if (!changesState.pair) return;
  const sequence=++changesState.sequence, params=pairParams();
  params.set("offset",changesState.offset); params.set("limit",25);
  if ($("change-category").value) params.set("category",$("change-category").value);
  if ($("change-type").value) params.set("status",$("change-type").value);
  $("change-previous").disabled=true; $("change-next").disabled=true;
  $("change-records").replaceChildren(node("p","Comparing observed inventories…","muted"));
  try {
    const result=await request(`/api/changes?${params}`); if (sequence!==changesState.sequence) return;
    const summary=result.summary;
    $("change-status").textContent=`${summary.host.name} · ${summary.host.platform} · baseline ${summary.baseline_interval[1]} → current ${summary.current_interval[1]}. Exact change time and actor are unknown.`;
    $("change-summary").replaceChildren(); const counts=node("div",undefined,"counts");
    for (const [label,value] of Object.entries(summary.counts)) { const card=node("div",undefined,"count"); card.append(node("strong",String(value)),node("span",label)); counts.append(card); }
    const coverage=node("p", summary.coverage.map((entry)=>`${entry.category}: ${entry.comparable ? "compared" : "not compared (coverage/scope)"}`).join(" · "),"small warnings");
    $("change-summary").append(counts,coverage,node("p","These are field differences in complete matching scopes. No differences does not establish safety.","small muted"));
    const evidence=node("details"); evidence.append(node("summary","Snapshot hashes, observation intervals, and coverage"),node("pre",JSON.stringify(summary,null,2))); $("change-summary").append(evidence);
    $("change-records").replaceChildren();
    for (const entry of result.items) $("change-records").append(changeCard(entry,changesState.pair));
    if (!result.items.length) $("change-records").append(node("p","No matching differences. Check category coverage before drawing conclusions.","muted"));
    $("change-page").textContent=result.total ? `${changesState.offset+1}–${Math.min(changesState.offset+25,result.total)} of ${result.total}` : "0 differences";
    $("change-previous").disabled=changesState.offset===0; $("change-next").disabled=changesState.offset+25>=result.total;
    $("change-reports").hidden=false; $("change-json").href=`/api/change-report?${pairParams()}&format=json`; $("change-text").href=`/api/change-report?${pairParams()}&format=text`;
  } catch(error) { if (sequence!==changesState.sequence) return; $("change-records").replaceChildren(); $("change-reports").hidden=true; $("change-status").textContent=error.message; }
}
function changeCard(entry,pair) {
  const card=node("article",undefined,`record change-${entry.status}`);
  card.append(node("div",`${entry.status.toUpperCase()} · ${entry.category} · ${entry.item_id}${entry.field ? ` · ${entry.field}` : ""}`,"record-head"));
  const values=node("div",undefined,"before-after");
  for (const label of ["before","after"]) { const cell=node("div"); cell.append(node("strong",label==="before" ? "Baseline value" : "Current value"),node("pre",entry[label] ?? "Not observed / unknown")); values.append(cell); } card.append(values);
  if(entry.preview_truncated) card.append(node("p","Value preview is shortened; expand the original item evidence for complete values.","small muted"));
  const details=node("details"), body=node("div"); details.append(node("summary","Review field evidence and configuration diff"),body); card.append(details);
  let loaded=false;
  details.addEventListener("toggle",async()=>{
    if (!details.open || loaded) return; loaded=true; body.textContent="Loading evidence…";
    try {
      const result=await request(`/api/changes/${entry.change_id}?${new URLSearchParams(pair)}`);
      body.replaceChildren();
      if (typeof result.text_diff === "string") body.append(node("h3","Configuration text diff"),node("pre",result.text_diff || "No textual line difference."));
      if (result.text_diff_note) body.append(node("p",result.text_diff_note,"warnings"));
      const source=node("details"); source.append(node("summary","Original snapshot items and source references"),node("pre",JSON.stringify(result,null,2))); body.append(source);
      const generate=node("button","Generate manual recovery plan","secondary"); generate.type="button";
      const recovery=node("div"); body.append(generate,recovery);
      generate.addEventListener("click",async()=>{
        if (!$("baseline-trust").checked || changesState.pair?.baseline_id!==pair.baseline_id || changesState.pair?.current_id!==pair.current_id) { recovery.textContent="Review the baseline evidence and check the trust acknowledgement for this pair first."; return; }
        generate.disabled=true;
        try {
          const plan=await request(`/api/changes/${entry.change_id}/recovery?${new URLSearchParams(pair)}`,{method:"POST",headers:{"Content-Type":"application/json","X-Sentinel-Import":"1"},body:JSON.stringify({baseline_trusted:true})});
          recovery.replaceChildren(node("p",plan.reason,"warnings"));
          for(const warning of plan.warnings) recovery.append(node("p",warning,"small muted"));
          if(plan.script) {
            recovery.append(node("h3",`Manual ${plan.shell} script`),node("pre",plan.script));
            const copy=node("button","Copy recovery script"), status=node("p","","small muted"); copy.type="button";
            copy.addEventListener("click",async()=>{ if(!$("baseline-trust").checked) {status.textContent="Baseline trust was cleared; review and confirm it again before copying.";return;} try { await navigator.clipboard.writeText(plan.script); status.textContent="Copied only. Review and run manually on the verified target host; recapture afterward."; } catch(_) { status.textContent="Clipboard unavailable; select the script text and copy manually."; } }); recovery.append(copy,status);
          }
        } catch(error) { recovery.textContent=error.message; } finally { generate.disabled=false; }
      });
    } catch(error) { body.textContent=error.message; loaded=false; }
  });
  return card;
}
$("snapshot-form").addEventListener("submit",async(event)=>{event.preventDefault(); const file=$("snapshot-file").files[0]; if (!file) return; if (file.size>4*1024*1024) {$("snapshot-status").textContent="Snapshot exceeds 4 MiB."; return;} busy(true); invalidate(); try {const item=await request(`/api/uploads?format=snapshot&filename=${encodeURIComponent(file.name)}`,{method:"POST",headers:{"Content-Type":"application/json","X-Sentinel-Import":"1"},body:file}); await loadSnapshots(item.id); $("snapshot-status").textContent=`Imported ${item.accepted_count} inventory items; ${item.warning_count} incomplete sections.`;} catch(error) {$("snapshot-status").textContent=error.message;} finally {busy(false);} });
$("compare-form").addEventListener("submit",(event)=>{event.preventDefault(); invalidate(); const baseline_id=$("baseline-select").value,current_id=$("current-select").value; if (!baseline_id || !current_id) return; changesState.pair={baseline_id,current_id}; loadChanges();});
for(const id of ["baseline-select","current-select"]) $(id).addEventListener("change",invalidate);
$("change-filters").addEventListener("submit",(event)=>{event.preventDefault(); changesState.offset=0; loadChanges();});
$("change-previous").addEventListener("click",()=>{changesState.offset=Math.max(0,changesState.offset-25);loadChanges();});
$("change-next").addEventListener("click",()=>{changesState.offset+=25;loadChanges();});
$("refresh-snapshots").addEventListener("click",async()=>{invalidate();try{await loadSnapshots();}catch(error){$("change-status").textContent=error.message;}});
$("delete-snapshot").addEventListener("click",async()=>{const id=$("current-select").value;if(!id || !window.confirm("Delete this current snapshot's retained local copy? Your original export remains unchanged."))return;busy(true);invalidate();try{await request(`/api/uploads/${id}`,{method:"DELETE",headers:{"X-Sentinel-Import":"1"}});await loadSnapshots();}catch(error){$("change-status").textContent=error.message;}finally{busy(false);}});
request("/api/auth/me").then((user)=>{$("change-user").textContent=`Signed in as ${user.username}`;}).catch(()=>{});
$("change-logout").addEventListener("click",async()=>{try{await request("/api/auth/logout",{method:"POST",headers:{"X-Sentinel-Import":"1"}});window.location.replace("/login");}catch(error){$("change-status").textContent=error.message;}});
loadSnapshots(new URLSearchParams(window.location.search).get("current")).catch((error)=>{$("change-status").textContent=error.message;});
