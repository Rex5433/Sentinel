import assert from "node:assert/strict";
import {test} from "node:test";
import {buildCommand, commandFields, commandTitle, GROUPS} from "../../app/static/mysql-templates.mjs";

const values = {
  database: "app-db", table: "devices", columns: "id, status", limit: "25", user: "reporter", host: "localhost",
  serverUuid: "D3A0B576-B5AC-4ABC-995D-3C423A2153F2",
  keyColumn: "id", keyType: "integer", keyValue: "42", column: "status",
  oldType: "text", oldValue: "ready", newType: "text", newValue: "needs review", reviewed: true,
  filterColumn: "status", filterOperator: "text-eq", filterValue: "ready",
  sortColumn: "id", sortDirection: "DESC", serverHost: "127.0.0.1", port: "3306", outputFile: "app-schema.sql",
};
const serverMatch = "LOWER(@@server_uuid) = 'd3a0b576-b5ac-4abc-995d-3c423a2153f2'";

test("every task builds a documented recipe for MySQL 8.0 and 8.4", () => {
  for (const version of ["8.0", "8.4"]) {
    for (const task of GROUPS.flatMap(([, tasks]) => tasks)) {
      const command = buildCommand(task, version, values);
      assert.equal(command.title, commandTitle(task));
      assert.ok(command.permissions && command.expected);
      assert.ok(commandFields(task).every(field => Object.hasOwn(values, field)));
      assert.equal(command.steps.filter(step => step.write).length, task === "update" ? 1 : 0);
      for (const step of command.steps.filter(step => !step.write)) {
        if (step.command) {
          assert.match(step.command, /^mysql(?:dump)? --protocol=TCP /);
          assert.equal(step.sql, undefined);
        } else {
          assert.match(step.sql, /^(?:(?:SHOW|SELECT)[^;]+;\s*)+$/);
        }
      }
    }
  }
});

test("version discovery works before selecting a supported version", () => {
  assert.match(buildCommand("identity", "").steps[0].sql, /SELECT VERSION\(\)/);
  assert.doesNotMatch(buildCommand("identity", "").steps[0].sql, /@@server_uuid/);
  assert.match(buildCommand("identity", "8.4").steps[0].sql, /@@server_uuid/);
  for (const version of ["", "5.7", "MariaDB", "9.0"]) {
    assert.throws(() => buildCommand("tables", version, values), /choose MySQL 8\.0 or 8\.4/);
  }
  assert.throws(() => buildCommand("__proto__", "8.4", values), /supported task/);
});

test("filtered queries use fixed operators, optional ordering, and bounded output", () => {
  const filter = input => buildCommand("filter", "8.4", {...values, ...input}).steps[0].sql;
  const count = input => buildCommand("count", "8.0", {...values, ...input}).steps[0].sql;
  assert.equal(filter({filterColumn: "id", filterOperator: "integer-gte", filterValue: "9007199254740993"}),
    "SELECT `id`, `status` FROM `app-db`.`devices` WHERE `id` >= 9007199254740993 ORDER BY `id` DESC LIMIT 25;");
  assert.match(filter({filterOperator: "text-contains", filterValue: "%_'\u2603", sortColumn: ""}),
    /WHERE LOCATE\(X'255f27e29883', CAST\(CONVERT\(`status` USING utf8mb4\) AS BINARY\)\) > 0 LIMIT 25;/);
  assert.match(count({filterOperator: "text-eq", filterValue: ""}), /AS BINARY\) <=> X'';/);
  assert.equal(count({filterOperator: "is-not-null", filterValue: undefined}),
    "SELECT COUNT(*) AS matched_rows FROM `app-db`.`devices` WHERE `status` IS NOT NULL;");
  for (const input of [{filterColumn: "id; DROP"}, {filterOperator: "is-null; SELECT"}, {filterOperator: "__proto__"},
    {filterOperator: "integer-eq", filterValue: "1 OR TRUE"}, {filterOperator: "text-contains", filterValue: ""},
    {sortColumn: "id, password"}, {sortDirection: "DESC; SHOW TABLES"}, {limit: "101"}]) {
    assert.throws(() => filter(input));
  }
});

test("OS commands prompt for credentials and dump one schema without rows", () => {
  const connect = buildCommand("connect", "", values).steps[0];
  assert.equal(connect.command,
    "mysql --protocol=TCP --host=127.0.0.1 --port=3306 --user=reporter --password --database=app-db");
  assert.ok(!buildCommand("connect", "", {...values, database: ""}).steps[0].command.includes("--database="));
  const backup = input => buildCommand("schema-backup", "8.4", {...values, ...input}).steps[0].command;
  assert.match(backup({outputFile: ""}), /--no-data --routines --events --triggers.*--result-file=app-db-schema\.sql --databases app-db$/);
  assert.ok(backup().includes("--skip-lock-tables --skip-add-drop-table"));
  for (const input of [{serverHost: "db.example & whoami"}, {serverHost: "db%PATH%"}, {port: "0"},
    {port: "65536"}, {port: "3306\n"}, {user: "x; whoami"}, {user: "$env"}, {database: "app$HOME"},
    {database: "performance_schema"}, {outputFile: "CON.sql"}, {outputFile: "../schema.sql"},
    {outputFile: "C:\\temp\\schema.sql"}, {outputFile: "schema.sql > secret.sql"}]) {
    assert.throws(() => backup(input));
  }
});

test("table preview requires explicit columns and bounds row count", () => {
  assert.equal(buildCommand("preview", "8.4", values).steps[0].sql,
    "SELECT `id`, `status` FROM `app-db`.`devices` LIMIT 25;");
  for (const limit of ["", "0", "101", "1e2", "25; SHOW DATABASES"]) {
    assert.throws(() => buildCommand("preview", "8.4", {...values, limit}), /whole number/);
  }
  for (const columns of ["*", "id, ", "id, SLEEP(1)", Array(11).fill("id").join(",")]) {
    assert.throws(() => buildCommand("preview", "8.4", {...values, columns}));
  }
});

test("object, account and host input cannot introduce SQL or mysql client commands", () => {
  for (const table of ["bad`name", "db.table", "a;DROP", "a\\!cmd", "a\nQUIT", "a\u2028", "a".repeat(65)]) {
    assert.throws(() => buildCommand("definition", "8.4", {...values, table}), /Table must use/);
  }
  assert.throws(() => buildCommand("account-grants", "8.4", {...values, host: "host' ; SHOW DATABASES; --"}), /host part/);
  assert.throws(() => buildCommand("account-grants", "8.4", {...values, user: "admin'@'%"}), /supported MySQL username/);
  assert.equal(buildCommand("account-grants", "8.4", {...values, host: "192.0.2.%"}).steps[0].sql,
    "SHOW GRANTS FOR 'reporter'@'192.0.2.%';");
});

test("manual capture includes server identity and one exact object scope", () => {
  const schema = buildCommand("schema-capture", "8.0", values).steps[0].sql;
  assert.match(schema, /@@server_uuid/);
  assert.match(schema, /SHOW CREATE TABLE `app-db`\.`devices`;/);
  assert.match(schema, /SHOW FULL COLUMNS FROM `app-db`\.`devices`;/);
  assert.match(schema, /SHOW INDEX FROM `app-db`\.`devices`;/);
  const grant = buildCommand("grant-capture", "8.4", values).steps[0].sql;
  assert.match(grant, /@@server_uuid/);
  assert.match(grant, /SHOW GRANTS FOR 'reporter'@'localhost';/);
});

test("exact row lookup checks text bytes as well as the indexed key", () => {
  const result = buildCommand("lookup", "8.4", {...values, keyType: "text", keyValue: "ALPHA"}).steps[0].sql;
  assert.match(result, /WHERE `id` = CONVERT\(X'414c504841' USING utf8mb4\) AND CAST\(CONVERT\(`id` USING utf8mb4\) AS BINARY\) <=> X'414c504841' LIMIT 2;$/);
});

test("update requires confirmed scope and a nonempty key distinct from the changed column", () => {
  assert.throws(() => buildCommand("update", "8.4", {...values, reviewed: false}), /Confirm/);
  assert.throws(() => buildCommand("update", "8.4", {...values, keyValue: "", keyType: "text"}), /nonempty/);
  assert.throws(() => buildCommand("update", "8.4", {...values, keyValue: "", keyType: "null"}), /non-NULL/);
  assert.throws(() => buildCommand("update", "8.4", {...values, column: "ID"}), /different column/);
  assert.throws(() => buildCommand("update", "8.4", {...values, keyValue: "42 OR 1=1"}), /valid integer/);
  for (const serverUuid of ["", "abc", "x' OR 1 = 1 --"]) {
    assert.throws(() => buildCommand("update", "8.4", {...values, serverUuid}), /approved server UUID/);
  }
});

test("update emits preview, guarded statement, and verification as separate steps", () => {
  const raw = "雪'\\; DROP TABLE devices;";
  const {steps} = buildCommand("update", "8.4", {...values, oldType: "null", oldValue: "", newValue: raw});
  const hex = Buffer.from(raw).toString("hex");
  assert.ok(steps[0].sql.endsWith(`SHOW INDEX FROM \`app-db\`.\`devices\`;\nSELECT \`id\`, \`status\` FROM \`app-db\`.\`devices\` WHERE ${serverMatch} AND \`id\` <=> 42 LIMIT 2;`));
  assert.equal(steps[1].sql, `UPDATE \`app-db\`.\`devices\` SET \`status\` = CONVERT(X'${hex}' USING utf8mb4) WHERE ${serverMatch} AND \`id\` <=> 42 AND \`status\` <=> NULL LIMIT 1;`);
  assert.ok(!steps[1].sql.includes(raw));
  assert.match(steps[2].sql, /^SHOW WARNINGS;\nSELECT /);
});

test("update guards exact old text, supports empty text, and retains full integer precision", () => {
  const command = buildCommand("update", "8.0", {...values, keyValue: "18446744073709551615", newValue: ""});
  assert.ok(command.steps[1].sql.includes(`SET \`status\` = CONVERT(X'' USING utf8mb4) WHERE ${serverMatch} AND \`id\` <=> 18446744073709551615`));
  assert.match(command.steps[1].sql, /CAST\(CONVERT\(`status` USING utf8mb4\) AS BINARY\) <=> X'7265616479'/);
  for (const keyValue of ["18446744073709551616", "-9223372036854775809", "4.5", "42\n"]) {
    assert.throws(() => buildCommand("update", "8.0", {...values, keyValue}), /valid integer/);
  }
  assert.throws(() => buildCommand("update", "8.0", {...values, newValue: "x".repeat(1025)}), /valid text/);
});
