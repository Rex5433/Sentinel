"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const api = "/api/wazuh/tools";
  const node = (tag, text, css) => {
    const el = document.createElement(tag);
    if (text != null) el.textContent = text;
    if (css) el.className = css;
    return el;
  };
  const states = {connected: "SSH verified", network: "Disconnected", authentication: "Authentication failed",
    host_key: "Host key untrusted", timeout: "Timeout", not_configured: "Not configured",
    nmap_unavailable: "Nmap unavailable", untested: "Connection saved · select Test connection"};
  async function request(path, method = "GET", data) {
    const headers = method === "GET" ? {} : {"X-Sentinel-Import": "1"};
    if (data !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {method, headers, cache: "no-store", signal: AbortSignal.timeout(45000),
      body: data === undefined ? undefined : JSON.stringify(data)});
    if (response.status === 401) window.location.replace("/login");
    if (response.status === 204) return null;
    const payload = await response.json();
    if (!response.ok) {
      const detail = payload.detail;
      const error = Error(typeof detail === "string" ? detail :
        detail?.message ? [states[detail.state], detail.message].filter(Boolean).join(" · ") : "Check the submitted values.");
      error.detail = detail;
      throw error;
    }
    return payload;
  }
  function announce(id, text, error = false) {
    $(id).textContent = text;
    $(id).classList.toggle("error", error);
  }
  function values(form) { return Object.fromEntries(new FormData(form)); }
  function wire(id, status, action) {
    $(id).addEventListener("submit", async event => {
      event.preventDefault();
      const button = event.submitter;
      if (button) button.disabled = true;
      try { await action(event.currentTarget, button); }
      catch (error) { announce(status, error.message, true); }
      finally { if (button) button.disabled = false; }
    });
  }
  function option(value, text) { return new Option(text, value); }
  function action(text, handler) {
    const button = node("button", text, "secondary");
    button.type = "button";
    button.addEventListener("click", handler);
    return button;
  }
  function messageBlock(text) { return node("p", text, "small muted"); }

  const ssh = $("wazuh-ssh");
  const keyDialog = $("wazuh-host-key");
  let savedProfile = false;
  let sshBusy = false;
  function updateAuth() {
    const key = ssh.elements.authentication.value === "key";
    $("wazuh-password-label").hidden = key;
    $("wazuh-key-label").hidden = !key;
    ssh.elements.password.disabled = key;
    ssh.elements.identity_file.disabled = !key;
  }
  ssh.elements.authentication.addEventListener("change", updateAuth);
  const reveal = $("wazuh-password-toggle");
  reveal.addEventListener("click", () => {
    const visible = ssh.elements.password.type === "password";
    ssh.elements.password.type = visible ? "text" : "password";
    reveal.setAttribute("aria-pressed", visible);
    reveal.setAttribute("aria-label", visible ? "Hide password" : "Show password");
  });
  function connectionStatus(status) {
    announce("wazuh-ssh-state", [states[status.state], status.version, status.message].filter(Boolean).join(" · "),
      !["connected", "untested", "not_configured"].includes(status.state));
  }
  function applySettings(settings, initial = false) {
    savedProfile = Boolean(settings.profile && (settings.profile.authentication === "key" || settings.password_available));
    if (initial) {
      for (const [key, value] of Object.entries(settings.profile ?? {})) ssh.elements[key].value = value;
      $("wazuh-dashboard").elements.url.value = settings.dashboard_url;
      $("wazuh-dashboard-link").href = settings.dashboard_url;
      updateAuth();
    }
    ssh.elements.password.placeholder = settings.password_available ? "Leave blank to reuse for the saved profile" : "";
    connectionStatus(settings.status);
    if (settings.profile?.authentication === "password" && !settings.password_available) {
      announce("wazuh-ssh-state", "Enter and save the SSH password for this session.");
    }
    updateScanControls();
  }
  wire("wazuh-ssh", "wazuh-ssh-state", async (form, button) => {
    if (sshBusy) return;
    const operation = button?.value || "save";
    const payload = values(form);
    payload.port = Number(payload.port);
    if (!payload.password) delete payload.password;
    form.elements.password.type = "password";
    reveal.setAttribute("aria-pressed", false);
    reveal.setAttribute("aria-label", "Show password");
    announce("wazuh-ssh-state", operation === "test" ? "Testing SSH and remote Nmap…" : "Saving connection…");
    const path = `${api}/connection/${operation}`;
    sshBusy = true;
    try {
      let result;
      try { result = await request(path, "POST", payload); }
      catch (error) {
        const info = error.detail;
        if (info?.state !== "approval_required") throw error;
        $("wazuh-host-key-details").textContent = `${info.host} · Port ${info.port} · ${info.key_type} · ${info.fingerprint}`;
        const approved = await new Promise(resolve => {
          keyDialog.returnValue = "cancel";
          keyDialog.addEventListener("close", () => resolve(keyDialog.returnValue === "approve"), {once: true});
          keyDialog.showModal();
        });
        if (!approved) { announce("wazuh-ssh-state", "SSH host key approval cancelled."); return; }
        result = await request(path, "POST", {...payload, approval: info.approval});
      }
      if (operation === "save") {
        form.elements.password.value = "";
        applySettings(result);
      } else connectionStatus(result);
    } finally { sshBusy = false; }
  });
  wire("wazuh-dashboard", "wazuh-dashboard-state", async form => {
    const result = await request(api + "/dashboard", "POST", values(form));
    form.elements.url.value = result.url;
    $("wazuh-dashboard-link").href = result.url;
    announce("wazuh-dashboard-state", "Dashboard URL saved.");
  });

  let scans = [];
  let activeScan = null;
  let scannerBusy = false;
  const scan = $("nmap-scan");
  function updateScanControls() {
    $("nmap-start").disabled = !savedProfile || Boolean(activeScan) || scannerBusy || !scan.elements.target.value;
    $("nmap-stop").disabled = !activeScan || activeScan.status === "stopping";
    $("nmap-port-label").hidden = scan.elements.profile.value === "discovery";
  }
  function renderScan() {
    const result = scans.find(item => item.id === $("nmap-history").value);
    const output = $("nmap-results");
    output.replaceChildren();
    if (!result) { output.append(messageBlock("No scans saved.")); return; }
    output.append(messageBlock([result.target, result.address, result.status, result.timestamp,
      result.duration_ms != null && `${(result.duration_ms / 1000).toFixed(1)} s`, result.error].filter(Boolean).join(" · ")));
    if (result.host_state) {
      const assumed = result.host_reason === "user-set" ? "Up assumed by TCP-only scan" : result.host_state;
      output.append(messageBlock(`Host status · ${assumed}`));
    }
    if (result.comparison) {
      const labels = {new_open: "Newly open", now_closed: "Now closed", now_filtered: "Now filtered"};
      const changes = Object.entries(result.comparison).filter(([, ports]) => ports.length).map(([key, ports]) => `${labels[key]} ${ports.join(", ")}`);
      output.append(messageBlock(changes.length ? `Review observations · ${changes.join(" · ")}` : "No comparable port changes."));
      if (changes.length) {
        const link = node("a", "View target observations in Timeline", "small");
        link.href = `/?${new URLSearchParams({tool: "timeline", source_kind: "nmap", host: result.address})}`;
        output.append(link);
      }
    } else if (result.ports) output.append(messageBlock("First comparable scan."));
    if (!result.ports?.length) return;
    const wrapper = node("div", null, "siem-table-scroll");
    const table = node("table");
    const head = table.createTHead().insertRow();
    for (const title of ["Port", "State", "Service", "Version"]) head.append(node("th", title));
    const tbody = table.createTBody();
    for (const port of result.ports) {
      const row = tbody.insertRow();
      for (const value of [`${port.port}/${port.protocol}`, port.state, port.service, port.version]) row.append(node("td", value || "—"));
    }
    wrapper.append(table);
    output.append(wrapper);
  }
  async function refreshScanner() {
    if (scannerBusy) return;
    scannerBusy = true;
    try {
      const result = await request(api + "/nmap");
      if (activeScan && !result.active) request(api).then(settings => applySettings(settings)).catch(() => {});
      activeScan = result.active;
      const current = scan.elements.target.value;
      scan.elements.target.replaceChildren(option("", "Select an authorized target"), ...result.targets.map(target =>
        option(target.id, `${target.name} · ${target.address}${target.sensitive ? " · Sensitive" : ""}`)));
      if (result.targets.some(target => target.id === current)) scan.elements.target.value = current;
      $("nmap-targets").replaceChildren(...result.targets.map(target => {
        const row = node("div", null, "actions");
        row.append(messageBlock(`${target.name} · ${target.address}`), action("Remove", async () => {
          try { await request(`${api}/nmap/targets/${target.id}`, "DELETE"); await refreshScanner(); }
          catch (error) { announce("nmap-state", error.message, true); }
        }));
        return row;
      }));
      const previousLatest = scans[0]?.id;
      const selected = $("nmap-history").value;
      scans = result.history;
      $("nmap-history").replaceChildren(...(scans.length ? scans.map(row => option(row.id, `${row.target} · ${row.status} · ${row.timestamp}`)) : [option("", "No scans saved")]));
      if (selected !== previousLatest && scans.some(row => row.id === selected)) $("nmap-history").value = selected;
      announce("nmap-state", activeScan ? `${activeScan.target} · ${activeScan.status} · ${Math.max(0, Math.floor((Date.now() - Date.parse(activeScan.timestamp)) / 1000))} s` :
        result.error ?? (scans[0] ? `Latest scan ${scans[0].status}` : ""), Boolean(result.error || (!activeScan && scans[0]?.status === "failed")));
      renderScan();
    } catch (error) { announce("nmap-state", error.message, true); }
    finally { scannerBusy = false; updateScanControls(); }
  }
  scan.addEventListener("change", updateScanControls);
  $("nmap-history").addEventListener("change", renderScan);
  wire("nmap-target", "nmap-state", async form => {
    await request(api + "/nmap/targets", "POST", {...values(form), sensitive: form.elements.sensitive.checked});
    form.reset();
    await refreshScanner();
  });
  scan.addEventListener("submit", async event => {
    event.preventDefault();
    $("nmap-start").disabled = true;
    try {
      activeScan = await request(api + "/nmap/start", "POST", {...values(scan), authorized: scan.elements.authorized.checked});
      scan.elements.authorized.checked = false;
      await refreshScanner();
    } catch (error) { announce("nmap-state", error.message, true); }
    finally { updateScanControls(); }
  });
  $("nmap-stop").addEventListener("click", async () => {
    const scanId = activeScan?.id;
    if (!scanId) return;
    try { await request(`${api}/nmap/stop/${scanId}`, "POST"); await refreshScanner(); }
    catch (error) { await refreshScanner(); announce("nmap-state", error.message, true); }
  });
  $("siem-logout").addEventListener("click", async () => {
    const button = $("siem-logout");
    button.disabled = true;
    try { await request("/api/auth/logout", "POST"); window.location.replace("/login"); }
    catch (error) { announce("wazuh-ssh-state", error.message, true); button.disabled = false; }
  });
  request("/api/auth/me").then(user => { $("siem-user").textContent = `Signed in as ${user.username}`; }).catch(() => {});
  request(api).then(async settings => {
    applySettings(settings, true);
    if (!settings.profile || sshBusy || (settings.profile.authentication === "password" && !settings.password_available)) return;
    sshBusy = true;
    try {
      announce("wazuh-ssh-state", "Reconnecting to the Wazuh VM…");
      applySettings(await request(`${api}/connection/reconnect`, "POST"));
    } finally { sshBusy = false; }
  }).catch(error => announce("wazuh-ssh-state", error.message, true));
  refreshScanner();
  setInterval(() => { if (!document.hidden && activeScan) refreshScanner(); }, 1000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshScanner(); });
})();
