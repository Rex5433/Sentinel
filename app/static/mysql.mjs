import {buildCommand, commandFields, commandTitle, FILTER_OPERATORS, GROUPS} from "./mysql-templates.mjs";

const $ = id => document.getElementById(id);
const labels = {
  database: "Database name", table: "Table name", columns: "Columns (1–10, separated by commas)",
  serverUuid: "Approved server UUID (from server identity)",
  serverHost: "MySQL hostname or IPv4 address", port: "TCP port", outputFile: "Backup filename (optional)",
  limit: "Maximum rows (1–100)", user: "MySQL username", host: "Exact MySQL account host part",
  filterColumn: "Filter column", filterOperator: "Match", filterValue: "Filter value",
  sortColumn: "Sort column (optional)", sortDirection: "Sort direction",
  keyColumn: "Single-column unique key", keyType: "Key type", keyValue: "Key value",
  column: "Column to update", oldType: "Current value type", oldValue: "Current value",
  newType: "New value type", newValue: "New value",
  reviewed: "I confirmed the approved server and unique key and have a backup.",
};
const placeholders = {database: "app_db", table: "devices", columns: "id, status", user: "operator", host: "localhost",
  keyColumn: "id", column: "status", serverHost: "127.0.0.1", filterColumn: "status", sortColumn: "id",
  outputFile: "Defaults to database-schema.sql"};
const valueTypes = {integer: "Integer", text: "Text", null: "NULL"};
const selectOptions = {
  filterOperator: {"": "Choose a match", ...FILTER_OPERATORS},
  sortDirection: {ASC: "Ascending", DESC: "Descending"},
  keyType: {"": "Choose a key type", integer: "Integer", text: "Text"},
  oldType: {"": "Choose a value type", ...valueTypes},
  newType: {"": "Choose a value type", ...valueTypes},
};
const reusableFields = new Set(["database", "table", "columns", "serverHost", "port"]);
const context = {};

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function option(value, text) {
  const element = node("option", text);
  element.value = value;
  return element;
}

function clearOutput() {
  $("mysql-output").replaceChildren(node("p", "Build a command for the current selection.", "muted"));
  $("mysql-status").textContent = "";
}

function renderFields() {
  clearOutput();
  $("mysql-fields").replaceChildren();
  const task = $("mysql-task").value;
  for (const name of commandFields(task)) {
    const optionalDatabase = task === "connect" && name === "database";
    const label = node("label", optionalDatabase ? "Default database (optional)" : labels[name]);
    const choices = selectOptions[name];
    const control = node(choices ? "select" : "input");
    label.htmlFor = control.id = `mysql-field-${name}`;
    control.name = name;
    control.required = !optionalDatabase && !["oldValue", "newValue", "filterValue", "sortColumn", "outputFile"].includes(name);
    if (choices) {
      for (const [key, value] of Object.entries(choices)) control.append(option(key, value));
    } else if (name === "reviewed") {
      control.type = "checkbox";
      label.className = "trust-label";
      label.prepend(control);
      $("mysql-fields").append(label);
      continue;
    } else if (name === "limit" || name === "port") {
      control.type = "number";
      control.min = "1";
      control.max = name === "port" ? "65535" : "100";
      control.value = name === "port" ? "3306" : "25";
    } else {
      control.type = "text";
      control.spellcheck = false;
      control.maxLength = {columns: 650, host: 255, serverHost: 253, user: 32, serverUuid: 36,
        keyValue: 1024, oldValue: 1024, newValue: 1024, filterValue: 1024, outputFile: 84}[name] ?? 64;
      control.placeholder = placeholders[name] ?? "";
    }
    if (reusableFields.has(name) && Object.hasOwn(context, name)) control.value = context[name];
    $("mysql-fields").append(label, control);
  }
  const match = $("mysql-field-filterOperator");
  if (match) match.addEventListener("change", () => {
    $("mysql-field-filterValue").disabled = ["is-null", "is-not-null"].includes(match.value);
  });
  if (task === "update") {
    $("mysql-fields").append(node("p", "Leave a value field empty only for empty text or NULL. Compare the displayed current value against the preview before copying the update.", "small muted"));
  }
}

function renderCommand(command) {
  const output = $("mysql-output");
  output.replaceChildren(node("h3", command.title), node("p", `Permissions · ${command.permissions}`), node("p", `Expected output · ${command.expected}`));
  for (const note of command.notes) output.append(node("p", note, "small muted"));
  for (const step of command.steps) {
    const card = node("article", undefined, step.write ? "record review-flagged" : "record");
    const heading = node("h4", step.label);
    const text = step.command ?? step.sql;
    const code = node("pre", text);
    const copy = node("button", step.write ? "Copy update statement" : step.command ? "Copy command" : "Copy SQL", "secondary");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        $("mysql-status").textContent = step.command ? "Copied for the operating-system shell." : "Copied for the mysql> prompt.";
      } catch {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(code);
        selection.removeAllRanges();
        selection.addRange(range);
        $("mysql-status").textContent = "Command selected. Copy it with your keyboard.";
      }
    });
    card.append(heading, code, copy);
    output.append(card);
  }
}

for (const [group, tasks] of GROUPS) {
  const choices = node("optgroup");
  choices.label = group;
  for (const task of tasks) choices.append(option(task, commandTitle(task)));
  $("mysql-task").append(choices);
}
$("mysql-task").addEventListener("change", renderFields);
$("mysql-form").addEventListener("input", event => {
  const {name, value} = event.target;
  if (reusableFields.has(name)) context[name] = value;
  clearOutput();
});
$("mysql-form").addEventListener("submit", event => {
  event.preventDefault();
  try {
    const values = Object.fromEntries(new FormData(event.currentTarget));
    values.reviewed = $("mysql-field-reviewed")?.checked === true;
    renderCommand(buildCommand($("mysql-task").value, $("mysql-version").value, values));
    $("mysql-status").textContent = "Command ready for review.";
  } catch (error) {
    clearOutput();
    $("mysql-status").textContent = error.message;
  }
});
renderFields();

fetch("/api/auth/me", {cache: "no-store"}).then(async response => {
  if (response.status === 401) window.location.replace("/login");
  if (response.ok) $("mysql-user").textContent = `Signed in as ${(await response.json()).username}`;
}).catch(() => { $("mysql-status").textContent = "Could not verify the session."; });

$("mysql-logout").addEventListener("click", async () => {
  try {
    const response = await fetch("/api/auth/logout", {method: "POST", headers: {"X-Sentinel-Import": "1"}});
    if (!response.ok && response.status !== 401) throw new Error("Sign-out failed.");
    window.location.replace("/login");
  } catch (error) {
    $("mysql-status").textContent = error.message;
  }
});
