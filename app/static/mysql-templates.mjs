const IDENTIFIER = /^[A-Za-z0-9_$][A-Za-z0-9_$-]{0,63}$/;
const SERVER_UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const MYSQL_VERSIONS = new Set(["8.0", "8.4"]);
const IDENTITY = "SELECT VERSION() AS mysql_version, @@hostname AS server_host, @@port AS server_port, @@server_uuid AS server_uuid, CURRENT_USER() AS effective_account;";
const metadata = "Metadata visibility depends on the signed-in account. Empty or denied output can indicate limited access.";

const INTEGER_OPERATORS = {eq: "=", gt: ">", gte: ">=", lt: "<", lte: "<="};
export const FILTER_OPERATORS = {
  "text-eq": "Text equals (case-sensitive)",
  "text-contains": "Text contains (case-sensitive)",
  "integer-eq": "Integer equals",
  "integer-gt": "Integer greater than",
  "integer-gte": "Integer at least",
  "integer-lt": "Integer less than",
  "integer-lte": "Integer at most",
  "is-null": "Is NULL",
  "is-not-null": "Is not NULL",
};

function identifier(value, name) {
  if (typeof value !== "string" || !IDENTIFIER.test(value) || /[\r\n]$/.test(value)) {
    throw new Error(`${name} must use 1–64 letters, digits, underscores, dollar signs or hyphens. Enter the name without quotes.`);
  }
  return "`" + value + "`";
}

function textLiteral(value, name) {
  if (typeof value !== "string" || value.length > 1024 || /\p{Surrogate}/u.test(value)) {
    throw new Error(`${name} must be valid text of 1,024 characters or fewer.`);
  }
  const bytes = Array.from(new TextEncoder().encode(value), byte => byte.toString(16).padStart(2, "0")).join("");
  return `X'${bytes}'`;
}

function typedValue(type, value, label) {
  if (type === "null" && (value === "" || value === undefined)) return {sql: "NULL"};
  if (type === "text") {
    const hex = textLiteral(value, label);
    return {sql: `CONVERT(${hex} USING utf8mb4)`, hex};
  }
  if (type === "integer" && typeof value === "string" && /^-?(?:0|[1-9][0-9]{0,19})$/.test(value) && !/[\r\n]$/.test(value)) {
    const integer = BigInt(value);
    if (integer >= -(2n ** 63n) && integer < 2n ** 64n) return {sql: integer.toString()};
  }
  throw new Error(`${label} needs a valid integer or text value. For NULL, leave the value box empty.`);
}

function equals(column, value) {
  if (value.hex) return `CAST(CONVERT(${column} USING utf8mb4) AS BINARY) <=> ${value.hex}`;
  return `${column} <=> ${value.sql}`;
}

function boundedLimit(value) {
  if (typeof value !== "string" || !/^(?:[1-9][0-9]?|100)$/.test(value) || /[\r\n]$/.test(value)) {
    throw new Error("The row limit must be a whole number from 1 to 100.");
  }
  return Number(value);
}

function selectedColumns(value) {
  const columns = typeof value === "string" && value.length <= 650 ? value.split(",") : [];
  if (!columns.length || columns.length > 10) throw new Error("Enter 1–10 column names separated by commas.");
  return columns.map(column => identifier(column.trim(), "Each column")).join(", ");
}

function table({database, table}) {
  return `${identifier(database, "Database")}.${identifier(table, "Table")}`;
}

function recipe(title, fields, permissions, expected, statements, notes = [metadata]) {
  return {title, fields, permissions, expected, statements, notes};
}

export const GROUPS = [
  ["Server and accounts", ["identity", "databases", "grants", "account-grants", "sessions", "log-settings"]],
  ["Tables and records", ["tables", "definition", "columns", "indexes", "preview", "filter", "count", "lookup"]],
  ["Terminal and backup", ["connect", "schema-backup"]],
  ["Baseline capture", ["schema-capture", "grant-capture"]],
  ["Manual change", ["update"]],
];

const TABLE_FIELDS = ["database", "table"];
const KEY_FIELDS = ["keyColumn", "keyType", "keyValue"];
const FILTER_FIELDS = ["filterColumn", "filterOperator", "filterValue"];
const CONNECTION_FIELDS = ["serverHost", "port", "user", "database"];
const recipes = {
  identity: recipe("Check server identity and version", [], "A working MySQL session.",
    "Server version, host, port and authenticated account. A supported version selection includes the server UUID.",
    (_, version) => MYSQL_VERSIONS.has(version) ? IDENTITY
      : "SELECT VERSION() AS mysql_version, @@hostname AS server_host, @@port AS server_port, CURRENT_USER() AS effective_account;", []),
  databases: recipe("List visible databases", [], "Access to the databases, or SHOW DATABASES for broader visibility.",
    "Database names visible to your session.", () => "SHOW DATABASES;"),
  grants: recipe("Show my grants", [], "Your current authenticated account.",
    "Grant and role statements for the current account.", () => "SHOW GRANTS FOR CURRENT_USER;"),
  "account-grants": recipe("Show grants for an account", ["user", "host"],
    "Permission to inspect the specified account's grants.",
    "Grant and role statements for the specified user and host.", accountGrants),
  sessions: recipe("Show current connections", [], "PROCESS to see other accounts’ sessions.",
    "Connection IDs, accounts, states and truncated statement text.", () => "SHOW PROCESSLIST;",
    ["Without PROCESS, visibility is limited to your account. Review output for sensitive statement text before sharing."]),
  "log-settings": recipe("Inspect server logging settings", [], "Access to the listed server variables.",
    "Current general and slow logging settings, log destination and error log path.",
    () => "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('general_log', 'slow_query_log', 'log_output', 'log_error');",
    ["The output records current settings. Log availability and retention require separate verification."]),
  tables: recipe("List tables and views", ["database"], "Access to the named database and visible objects.",
    "Visible object names with table or view type.", values => `SHOW FULL TABLES FROM ${identifier(values.database, "Database")};`),
  definition: recipe("Show table definition", TABLE_FIELDS, "A privilege on the named table.",
    "The CREATE statement reported by MySQL.", values => `SHOW CREATE TABLE ${table(values)};`),
  columns: recipe("List columns and types", TABLE_FIELDS, "A privilege on the named table.",
    "Column types, nullability, defaults, collation, keys and comments.",
    values => `SHOW FULL COLUMNS FROM ${table(values)};`),
  indexes: recipe("List indexes and keys", TABLE_FIELDS, "A privilege on the named table.",
    "Index names, uniqueness, component columns and column order.",
    values => `SHOW INDEX FROM ${table(values)};`),
  preview: recipe("Preview selected columns", [...TABLE_FIELDS, "columns", "limit"], "SELECT on the requested columns.",
    "Up to the selected number of rows from the named columns.",
    values => `SELECT ${selectedColumns(values.columns)} FROM ${table(values)} LIMIT ${boundedLimit(values.limit)};`,
    ["Choose only the columns you need. Row order is unspecified and the sample gives limited coverage."]),
  filter: recipe("Filter and sort rows", [...TABLE_FIELDS, "columns", ...FILTER_FIELDS, "sortColumn", "sortDirection", "limit"],
    "SELECT on the output, filter and sort columns.", "Up to the selected number of matching rows.",
    filteredSelect,
    ["Choose the filter that matches the column type. Text comparisons are case-sensitive and treat % and _ as literal characters.",
     "Text matching and sorting can scan many records. Review the scope before running on a large table."]),
  count: recipe("Count matching rows", [...TABLE_FIELDS, ...FILTER_FIELDS],
    "SELECT on the filter column.", "One count of all matching rows.",
    values => `SELECT COUNT(*) AS matched_rows FROM ${table(values)} WHERE ${rowFilter(values)};`,
    ["This counts every match. Use a selective filter on an indexed column for large tables."]),
  lookup: recipe("Look up a row by key", [...TABLE_FIELDS, ...KEY_FIELDS, "columns"], "SELECT on the requested columns and key.",
    "Up to two matches from the selected columns. Two matches mean the key did not identify a single row.", values => {
      const key = identifier(values.keyColumn, "Key column");
      return `SELECT ${selectedColumns(values.columns)} FROM ${table(values)} WHERE ${keyPredicate(key, values)} LIMIT 2;`;
    }, ["Check the column type and use an indexed key to keep the lookup focused."]),
  "schema-capture": recipe("Capture one table’s schema", TABLE_FIELDS, "A privilege on the named table.",
    "Server identity, table definition, columns and index metadata.",
    values => {
      const target = table(values);
      return `${IDENTITY}\nSHOW CREATE TABLE ${target};\nSHOW FULL COLUMNS FROM ${target};\nSHOW INDEX FROM ${target};`;
    },
    [metadata, "Keep the results together with capture time and any errors. Run the same statements on the same server and table for a later manual comparison."]),
  "grant-capture": recipe("Capture one account’s grants", ["user", "host"], "Permission to inspect the specified account’s grants.",
    "Server identity and grant statements for the selected account.", values => `${IDENTITY}\n${accountGrants(values)}`,
    [metadata, "Keep the results together with capture time and any errors. Repeat for the same account on the same server. Review inherited role privileges separately."]),
  connect: recipe("Open the MySQL terminal", CONNECTION_FIELDS, "An authorized MySQL login and the mysql client on PATH.",
    "A password prompt, then a mysql> session.",
    values => [{label: "Run in PowerShell, Command Prompt or Bash",
      command: `mysql ${connectionOptions(values)}${values.database ? ` --database=${shellDatabase(values.database)}` : ""}`}],
    ["Use the approved host and port. Enter your password at the terminal prompt."]),
  "schema-backup": recipe("Export a full database schema", [...CONNECTION_FIELDS, "outputFile"],
    "mysqldump on PATH and sufficient privileges to read the database objects.",
    "A SQL file with the selected database’s schema, including table and view definitions, triggers, routines and events visible to your account.",
    schemaBackup,
    ["Run from your approved backup directory and use a new filename. mysqldump can overwrite the file even if the export fails.",
     "The file contains object definitions. Table rows, account grants and tablespace definitions require a separate backup plan.",
     "Check the exit status and review definitions and DEFINER accounts before using the file for recovery."]),
  update: recipe("Prepare a guarded one-row update",
    ["serverUuid", ...TABLE_FIELDS, ...KEY_FIELDS, "column", "oldType", "oldValue", "newType", "newValue", "reviewed"],
    "SELECT and UPDATE on the named columns. Use a confirmed single-column unique key.",
    "The preview identifies the key and current value. The update directly matches at most one row. The last query shows the result.", updateStatements,
    ["Use supported integer or text columns. Verify their types and a single-column PRIMARY or UNIQUE index before proceeding.",
     "Compare the server UUID with the approved target. Back up the row and confirm the change scope. Run the preview and proceed only if exactly one expected row appears.",
     "Triggers and storage-engine behavior may have additional effects. Review these before running the statement. If MySQL reports zero rows changed, recheck the evidence."]),
};

function rowFilter({filterColumn, filterOperator, filterValue}) {
  const column = identifier(filterColumn, "Filter column");
  if (!Object.hasOwn(FILTER_OPERATORS, filterOperator)) throw new Error("Choose a supported filter.");
  if (filterOperator === "is-null") return `${column} IS NULL`;
  if (filterOperator === "is-not-null") return `${column} IS NOT NULL`;
  if (filterOperator === "text-eq") return equals(column, typedValue("text", filterValue, "Filter value"));
  if (filterOperator === "text-contains") {
    if (filterValue === "") throw new Error("Enter the text to find.");
    return `LOCATE(${textLiteral(filterValue, "Filter value")}, CAST(CONVERT(${column} USING utf8mb4) AS BINARY)) > 0`;
  }
  const operator = INTEGER_OPERATORS[filterOperator.slice("integer-".length)];
  return `${column} ${operator} ${typedValue("integer", filterValue, "Filter value").sql}`;
}

function filteredSelect(values) {
  let order = "";
  if (values.sortColumn) {
    if (!["ASC", "DESC"].includes(values.sortDirection)) throw new Error("Choose a supported sort direction.");
    order = ` ORDER BY ${identifier(values.sortColumn, "Sort column")} ${values.sortDirection}`;
  }
  return `SELECT ${selectedColumns(values.columns)} FROM ${table(values)} WHERE ${rowFilter(values)}${order} LIMIT ${boundedLimit(values.limit)};`;
}

function shellDatabase(value) {
  identifier(value, "Database");
  if (value.includes("$")) throw new Error("Shell commands require a database name without a dollar sign.");
  return value;
}

function connectionOptions({serverHost, port, user}) {
  if (typeof serverHost !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(serverHost)
      || /[\r\n]$/.test(serverHost)) throw new Error("Enter a hostname or IPv4 address without shell characters.");
  if (typeof port !== "string" || !/^[1-9][0-9]{0,4}$/.test(port) || /[\r\n]$/.test(port) || Number(port) > 65535) {
    throw new Error("Enter a TCP port from 1 to 65535.");
  }
  if (typeof user !== "string" || !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$/.test(user) || /[\r\n]$/.test(user)) {
    throw new Error("Enter a MySQL username using letters, digits, dot, hyphen or underscore.");
  }
  return `--protocol=TCP --host=${serverHost} --port=${port} --user=${user} --password`;
}

function schemaBackup(values) {
  const database = shellDatabase(values.database);
  if (["information_schema", "performance_schema", "mysql", "sys"].includes(database.toLowerCase())) {
    throw new Error("Choose an application database for the schema export.");
  }
  const file = values.outputFile || `${database}-schema.sql`;
  if (typeof file !== "string" || !/^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}\.sql$/i.test(file) || /[\r\n]$/.test(file)
      || /^(?:aux|con|nul|prn|com[0-9]|lpt[0-9])\.sql$/i.test(file)) {
    throw new Error("Enter a plain .sql filename with letters, digits, underscores or hyphens.");
  }
  return [{label: "Run in PowerShell, Command Prompt or Bash",
    command: `mysqldump ${connectionOptions(values)} --no-data --routines --events --triggers --no-tablespaces --set-gtid-purged=OFF --skip-lock-tables --skip-add-drop-table --skip-add-locks --result-file=${file} --databases ${database}`}];
}

function accountGrants({user, host}) {
  if (typeof user !== "string" || !/^[A-Za-z0-9_$.-]{1,32}$/.test(user) || /[\r\n]$/.test(user)) {
    throw new Error("Enter a supported MySQL username using letters, digits, dot, hyphen, underscore or dollar sign.");
  }
  if (typeof host !== "string" || !/^[A-Za-z0-9.:%_-]{1,255}$/.test(host) || /[\r\n]$/.test(host)) {
    throw new Error("Enter the account's exact MySQL host part, such as localhost, 192.0.2.8 or %.");
  }
  return `SHOW GRANTS FOR '${user}'@'${host}';`;
}

function keyPredicate(key, values) {
  const value = typedValue(values.keyType, values.keyValue, "Key value");
  if (value.sql === "NULL" || values.keyValue === "") throw new Error("Use a nonempty, non-NULL key.");
  const exact = equals(key, value);
  return value.hex ? `${key} = ${value.sql} AND ${exact}` : exact;
}

function updateStatements(values) {
  if (values.reviewed !== true) throw new Error("Confirm the approved target, unique key, and backup before building a change.");
  if (typeof values.serverUuid !== "string" || values.serverUuid.length !== 36 || !SERVER_UUID.test(values.serverUuid)) {
    throw new Error("Enter the approved server UUID from Check server identity and version.");
  }
  const target = table(values);
  const key = identifier(values.keyColumn, "Key column");
  const column = identifier(values.column, "Column to update");
  if (key.toLowerCase() === column.toLowerCase()) throw new Error("Choose a different column to update. The key remains fixed.");
  const targetMatch = `LOWER(@@server_uuid) = '${values.serverUuid.toLowerCase()}' AND ${keyPredicate(key, values)}`;
  const oldValue = typedValue(values.oldType, values.oldValue, "Current value");
  const newValue = typedValue(values.newType, values.newValue, "New value");
  const rowQuery = `SELECT ${key}, ${column} FROM ${target} WHERE ${targetMatch} LIMIT 2;`;
  return [
    {label: "1. Confirm identity, key and current value", sql: `${IDENTITY}\nSHOW FULL COLUMNS FROM ${target};\nSHOW INDEX FROM ${target};\n${rowQuery}`},
    {label: "2. Run the reviewed update manually", sql: `UPDATE ${target} SET ${column} = ${newValue.sql} WHERE ${targetMatch} AND ${equals(column, oldValue)} LIMIT 1;`, write: true},
    {label: "3. Check warnings and verify the resulting value", sql: `SHOW WARNINGS;\n${rowQuery}`},
  ];
}

export function commandFields(task) {
  return Object.hasOwn(recipes, task) ? recipes[task].fields : [];
}

export function commandTitle(task) {
  return Object.hasOwn(recipes, task) ? recipes[task].title : "";
}

export function buildCommand(task, version, values = {}) {
  if (!Object.hasOwn(recipes, task)) throw new Error("Choose a supported task.");
  if (!["identity", "connect"].includes(task) && !MYSQL_VERSIONS.has(version)) {
    throw new Error("Check the server identity first, then choose MySQL 8.0 or 8.4.");
  }
  const {title, permissions, expected, notes, statements} = recipes[task];
  const result = statements(values, version);
  return {title, permissions, expected, notes,
    steps: typeof result === "string" ? [{label: "Read-only SQL", sql: result}] : result};
}
