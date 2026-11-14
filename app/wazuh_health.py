"""Read-only Wazuh manager client and persistent agent observations."""

from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPException, HTTPSConnection
from ipaddress import ip_address
import json
import os
import re
import sqlite3
import ssl
from threading import Lock
from time import monotonic
from urllib.parse import urlencode, urlsplit

from sentinel.ingest.common import load_json

from .wazuh_events import normalize_transition, record_event


STATUSES = ("active", "disconnected", "pending", "never_connected", "unknown")
DEMO_MANAGER_ID = "sentinel-demo"
PAGE_SIZE = 100
MAX_AGENTS = 1_000
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
REQUEST_SECONDS = 5
POLL_BUDGET_SECONDS = 20


def _flag(env, name, default=False):
    value = env.get(f"SENTINEL_WAZUH_{name}", str(default)).strip().lower()
    if value in {"1", "true"}:
        return True
    if value in {"0", "false"}:
        return False
    raise ValueError(f"Set SENTINEL_WAZUH_{name} to true or false.")


def _seconds(env, name, default, low, high):
    value = env.get(f"SENTINEL_WAZUH_{name}", str(default)).strip()
    if not re.fullmatch(r"[0-9]{1,6}", value) or not low <= int(value) <= high:
        raise ValueError(f"Set SENTINEL_WAZUH_{name} to {low}–{high} seconds.")
    return int(value)


def _api_origin(value):
    if len(value) > 512 or re.search(r"[\s\\?#\x00-\x1f\x7f]", value):
        raise ValueError("Use an HTTPS Wazuh manager API origin.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.username is not None
                or parsed.path not in ("", "/") or not re.fullmatch(r"[a-zA-Z0-9.:-]+", host)):
            raise ValueError
        if parsed.port == 0:
            raise ValueError
        return host, parsed.port or 443
    except ValueError:
        raise ValueError("Use an HTTPS Wazuh manager API origin without credentials or a path.") from None


@dataclass(frozen=True)
class WazuhSettings:
    enabled: bool = False
    manager_id: str = "wazuh"
    demo: bool = False
    api_url: str = field(default="", repr=False)
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    ca_bundle: str = field(default="", repr=False)
    poll_seconds: int = 60
    disconnected_after_seconds: int | None = None
    alert_ingest_enabled: bool = False
    alert_ingest_token: str = field(default="", repr=False)
    error: str | None = None
    ingest_error: str | None = None

    def __post_init__(self):
        if self.demo:
            object.__setattr__(self, "manager_id", DEMO_MANAGER_ID)

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        values = {}
        try:
            if not _flag(env, "ENABLED"):
                return cls()
            demo = _flag(env, "DEMO")
            manager_id = DEMO_MANAGER_ID if demo else env.get("SENTINEL_WAZUH_MANAGER_ID", "wazuh").strip()
            if not demo and (manager_id == DEMO_MANAGER_ID or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", manager_id)):
                raise ValueError("Use a lowercase Wazuh manager ID with letters, digits, dots, hyphens or underscores.")
            values.update(manager_id=manager_id, demo=demo)
        except ValueError as exc:
            return cls(enabled=True, error=str(exc))

        try:
            if not demo and _flag(env, "ALERT_INGEST_ENABLED"):
                token = env.get("SENTINEL_WAZUH_ALERT_INGEST_TOKEN", "")
                if not re.fullmatch(r"[A-Za-z0-9._~-]{32,128}", token):
                    raise ValueError("Configure a Wazuh alert token with 32–128 URL-safe characters.")
                values.update(alert_ingest_enabled=True, alert_ingest_token=token)
        except ValueError as exc:
            values["ingest_error"] = str(exc)

        try:
            values["poll_seconds"] = _seconds(env, "AGENT_POLL_SECONDS", 60, 15, 3600)
            if demo:
                return cls(enabled=True, **values)
            if env.get("SENTINEL_WAZUH_AGENT_DISCONNECT_SECONDS", "").strip():
                values["disconnected_after_seconds"] = _seconds(env, "AGENT_DISCONNECT_SECONDS", 0, 1, 86400)
            if not _flag(env, "VERIFY_TLS", True):
                raise ValueError("Wazuh requires TLS verification. Configure a trusted CA bundle.")
            api_url = env.get("SENTINEL_WAZUH_API_URL", "").strip()
            username = env.get("SENTINEL_WAZUH_API_USERNAME", "").strip()
            password = env.get("SENTINEL_WAZUH_API_PASSWORD", "")
            if not api_url or not username or not password:
                raise ValueError("Configure the Wazuh HTTPS API URL and a restricted read-only API account.")
            _api_origin(api_url)
            if len(username) > 256 or ":" in username or len(password) > 2048:
                raise ValueError("The Wazuh API credentials have an invalid format.")
            ca_bundle = env.get("SENTINEL_WAZUH_CA_BUNDLE", "").strip()
            values.update(api_url=api_url, username=username, password=password, ca_bundle=ca_bundle)
        except ValueError as exc:
            values["error"] = str(exc)
        return cls(enabled=True, **values)


class WazuhApiError(RuntimeError):
    def __init__(self, message, *, state="degraded", status_code=None):
        super().__init__(message)
        self.state = state
        self.status_code = status_code


class WazuhApiClient:
    def __init__(self, settings):
        self.host, self.port = _api_origin(settings.api_url)
        self.tls = ssl.create_default_context()
        if settings.ca_bundle:
            try:
                self.tls.load_verify_locations(cafile=settings.ca_bundle)
            except (OSError, ValueError):
                raise ValueError("The Wazuh CA bundle could not be loaded.") from None
        encoded = b64encode(f"{settings.username}:{settings.password}".encode("utf-8")).decode("ascii")
        self.basic_auth = f"Basic {encoded}"
        self.token = None
        self.token_deadline = 0.0

    def _request(self, method, path, authorization, deadline, *, body=None, manager=True):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise WazuhApiError("The Wazuh request timed out.", state="timeout")
        # A direct HTTPS connection avoids proxy environment variables and redirects.
        connection = HTTPSConnection(self.host, self.port, context=self.tls, timeout=min(REQUEST_SECONDS, remaining))
        headers = {"Accept": "application/json", "Authorization": authorization}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            if body is None:
                connection.request(method, path, headers=headers)
            else:
                connection.request(method, path, body=body, headers=headers)
            with connection.getresponse() as response:
                status = response.status
                if not 200 <= status < 300:
                    if status in {401, 403}:
                        message = "The Wazuh API rejected authentication or access. Check the read-only account."
                    else:
                        message = f"The Wazuh API returned HTTP {status}."
                    state = "authentication_failed" if status == 401 else "permission_denied" if status == 403 else "unreachable" if status >= 500 else "degraded"
                    raise WazuhApiError(message, status_code=status, state=state)
                chunks = bytearray()
                while len(chunks) <= MAX_RESPONSE_BYTES:
                    if monotonic() >= deadline:
                        raise WazuhApiError("The Wazuh request timed out.", state="timeout")
                    data = response.read1(min(65_536, MAX_RESPONSE_BYTES + 1 - len(chunks)))
                    if not data:
                        break
                    chunks.extend(data)
                if len(chunks) > MAX_RESPONSE_BYTES:
                    raise WazuhApiError("The Wazuh API response exceeded the size limit.")
            payload = load_json(chunks.decode("utf-8"))
        except ssl.SSLCertVerificationError:
            raise WazuhApiError("Wazuh TLS certificate verification failed. Check the CA and API hostname.", state="tls_error") from None
        except TimeoutError:
            raise WazuhApiError("The Wazuh request timed out.", state="timeout") from None
        except (OSError, HTTPException):
            raise WazuhApiError("The Wazuh API could not be reached.", state="unreachable") from None
        except (ValueError, RecursionError):
            raise WazuhApiError("The Wazuh API returned an invalid response.") from None
        finally:
            connection.close()
        if not manager and isinstance(payload, dict):
            return payload
        if (not isinstance(payload, dict) or type(payload.get("error")) is not int
                or payload["error"] != 0 or not isinstance(payload.get("data"), dict)):
            raise WazuhApiError("The Wazuh API returned an incomplete response.")
        return payload["data"]

    def manager_details(self):
        started = monotonic()
        deadline = started + POLL_BUDGET_SECONDS
        info = _first_item(self._get("/manager/info", deadline))
        elapsed = round((monotonic() - started) * 1000)
        details = {"version": _text(info.get("version"), 64), "latency_ms": elapsed, "services": {}, "warning": None}
        try:
            status = _first_item(self._get("/manager/status", deadline))
            details["services"] = {key: value for key, value in status.items()
                                   if isinstance(key, str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", key)
                                   and value in ("running", "stopped", "failed", "restarting", "starting")}
        except WazuhApiError as exc:
            details["warning"] = str(exc)
        return details

    def agentless_logs(self):
        query = urlencode({"tag": "wazuh-agentlessd", "limit": 100, "sort": "-timestamp"})
        data = self._get(f"/manager/logs?{query}", monotonic() + REQUEST_SECONDS)
        rows = data.get("affected_items")
        if not isinstance(rows, list):
            raise WazuhApiError("The Manager returned an invalid log listing.")
        return rows[:100]

    def agentless_configuration(self):
        data = self._get("/manager/configuration?section=agentless", monotonic() + REQUEST_SECONDS)
        rows = _first_item(data).get("agentless", [])
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise WazuhApiError("The Manager returned an invalid agentless configuration.")
        return rows

    def _get(self, path, deadline):
        for attempt in range(2):
            if self.token is None or monotonic() >= self.token_deadline:
                auth = self._request("POST", "/security/user/authenticate", self.basic_auth, deadline)
                token = auth.get("token")
                if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{1,8192}", token):
                    raise WazuhApiError("The Wazuh API did not return a valid token.")
                self.token, self.token_deadline = token, monotonic() + 840
            try:
                return self._request("GET", path, f"Bearer {self.token}", deadline)
            except WazuhApiError as exc:
                if exc.status_code == 401:
                    self.token = None
                if attempt or exc.status_code != 401:
                    raise

    def fetch_agents(self):
        deadline = monotonic() + POLL_BUDGET_SECONDS
        rows, identities = [], set()
        previous_total = None
        while True:
            offset = len(rows)
            query = urlencode({"offset": offset, "limit": PAGE_SIZE, "sort": "+id",
                               "select": "id,name,ip,os,status,lastKeepAlive,dateAdd"})
            data = self._get(f"/agents?{query}", deadline)
            agents, total = data.get("affected_items"), data.get("total_affected_items")
            if (type(total) is not int or not 0 <= total <= MAX_AGENTS or not isinstance(agents, list)
                    or len(agents) != min(PAGE_SIZE, total - offset) or data.get("total_failed_items", 0) != 0
                    or (previous_total is not None and total != previous_total)):
                raise WazuhApiError("The Wazuh agent roster was partial, changed during paging, or exceeded the limit.")
            for agent in agents:
                identifier = agent.get("id") if isinstance(agent, dict) else None
                if not isinstance(identifier, str) or not re.fullmatch(r"[0-9]{3,8}", identifier) or identifier in identities:
                    raise WazuhApiError("The Wazuh agent roster contained invalid or repeated identities.")
                identities.add(identifier)
            rows.extend(agents)
            if len(rows) == total:
                break
            previous_total = total
        manager_counts = self._summary(deadline)
        return rows, manager_counts

    def _summary(self, deadline):
        try:
            summary = self._get("/agents/summary/status", deadline)
        except WazuhApiError:
            # The primary agent roster remains useful on releases or roles without this endpoint.
            return None
        counts = summary.get("connection", summary)
        if not isinstance(counts, dict):
            return None
        result = {status: counts.get(status) for status in STATUSES[:-1]}
        if any(type(count) is not int or count < 0 for count in result.values()):
            return None
        return result


def _first_item(data):
    rows = data.get("affected_items")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise WazuhApiError("The Manager returned no usable status record.")
    return rows[0]


class _DemoClient:
    def fetch_agents(self):
        return [
            {"id": "001", "name": "demo-linux", "ip": "192.0.2.21", "os": {"name": "Ubuntu"},
             "status": "active", "lastKeepAlive": "2026-11-11T12:00:00Z"},
            {"id": "002", "name": "demo-windows", "ip": "192.0.2.22", "os": {"name": "Windows"},
             "status": "disconnected", "lastKeepAlive": "2026-11-11T11:20:00Z"},
            {"id": "003", "name": "demo-pending", "status": "pending"},
            {"id": "004", "name": "demo-new", "status": "never_connected"},
        ], None


def _text(value, limit):
    if isinstance(value, str):
        return "".join(char for char in value[:limit] if char.isprintable()).strip() or None
    return None


def _timestamp(value):
    if isinstance(value, str) and len(value) <= 64:
        try:
            stamp = datetime.fromisoformat(value)
            if stamp.tzinfo is not None:
                return stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
        except (ValueError, OverflowError):
            pass
    return None


def _agent(row, manager_id, observed_at):
    agent_id = row["id"]
    status = _text(row.get("status"), 32) or "unknown"
    status = re.sub(r"[-\s]+", "_", status.casefold())
    os_data = row.get("os")
    if isinstance(os_data, dict):
        os_data = " ".join(part for part in [_text(os_data.get("name"), 80), _text(os_data.get("version"), 64)] if part)
    address = _text(row.get("ip"), 64)
    try:
        address = str(ip_address(address)) if address and "%" not in address else None
    except ValueError:
        address = None
    return {"manager_id": manager_id, "agent_id": agent_id,
            "agent_name": _text(row.get("name"), 128), "ip": address, "os": _text(os_data, 145),
            "status": status if status in STATUSES else "unknown", "last_keepalive": _timestamp(row.get("lastKeepAlive")),
            "observed_at": observed_at, "registered_at": _timestamp(row.get("dateAdd")), "changed_at": None}


class WazuhHealth:
    def __init__(self, store, settings, *, client=None):
        self.store = store
        self.settings = settings
        self.client = None
        self.lock = Lock()
        if not settings.enabled:
            self.initial = ("disabled", "Wazuh integration is disabled.")
        elif settings.error:
            self.initial = ("not_configured", settings.error)
        else:
            try:
                self.client = _DemoClient() if settings.demo else (client if client is not None else WazuhApiClient(settings))
                self.initial = ("degraded", "Waiting for the first Wazuh agent observation.")
            except ValueError as exc:
                self.initial = ("not_configured", str(exc))
        self.current = self.initial

    def initialize(self):
        with self.store.connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS wazuh_health_snapshots (
                manager_id TEXT PRIMARY KEY, observed_at TEXT, last_attempt_at TEXT NOT NULL,
                payload TEXT NOT NULL, diagnostics TEXT NOT NULL)""")

    def refresh(self):
        """Poll outside a transaction and publish only a complete roster."""
        if self.client is None:
            return
        with self.lock:
            try:
                rows, manager_counts = self.client.fetch_agents()
                observed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
                agents = [_agent(row, self.settings.manager_id, observed_at) for row in rows if row["id"] != "000"]
                self._save(agents, manager_counts, observed_at)
                message = "Synthetic demo data." if self.settings.demo else "Wazuh agent observations are current."
                self.current = ("connected", message)
            except WazuhApiError as exc:
                self.current = (exc.state, str(exc))
                try:
                    self._record_failure()
                except sqlite3.Error:
                    self.current = ("degraded", "The local store could not record the Wazuh poll result.")
            except (sqlite3.Error, ValueError, TypeError, KeyError):
                self.current = ("degraded", "The Wazuh agent observation could not be processed.")

    def _prior(self, connection):
        return connection.execute("SELECT * FROM wazuh_health_snapshots WHERE manager_id=?",
                                  (self.settings.manager_id,)).fetchone()

    def _save(self, agents, manager_counts, observed_at):
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = self._prior(connection)
            previous = {agent["agent_id"]: agent for agent in json.loads(prior["payload"])["agents"]} if prior else {}
            for agent in agents:
                before = previous.get(agent["agent_id"])
                if (not before or before["agent_name"] != agent["agent_name"]
                        or (before["registered_at"] and agent["registered_at"] and before["registered_at"] != agent["registered_at"])):
                    continue
                agent["changed_at"] = before["changed_at"]
                if agent["status"] != before["status"]:
                    agent["changed_at"] = observed_at
                    if {agent["status"], before["status"]} == {"active", "disconnected"} and not self.settings.demo:
                        record_event(connection, normalize_transition(
                            self.settings.manager_id, agent_id=agent["agent_id"], agent_name=agent["agent_name"],
                            ip=agent["ip"], timestamp=observed_at, previous_status=before["status"], status=agent["status"],
                        ))
            self._publish(connection, prior, observed_at, observed_at,
                          {"agents": agents, "manager_counts": manager_counts}, "connected", None)

    def _record_failure(self):
        stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        with self.store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = self._prior(connection)
            self._publish(connection, prior, prior["observed_at"] if prior else None, stamp,
                          json.loads(prior["payload"]) if prior else {"agents": [], "manager_counts": None}, *self.current)

    def _publish(self, connection, prior, observed_at, attempt_at, payload, state, message):
        diagnostics = json.loads(prior["diagnostics"]) if prior else []
        if not diagnostics or diagnostics[-1]["state"] != state or diagnostics[-1]["message"] != message:
            diagnostics.append({"timestamp": attempt_at, "state": state, "message": message})
        connection.execute("""INSERT INTO wazuh_health_snapshots
            (manager_id,observed_at,last_attempt_at,payload,diagnostics) VALUES (?,?,?,?,?)
            ON CONFLICT(manager_id) DO UPDATE SET observed_at=excluded.observed_at,
            last_attempt_at=excluded.last_attempt_at,payload=excluded.payload,diagnostics=excluded.diagnostics""",
                           (self.settings.manager_id, observed_at, attempt_at, json.dumps(payload), json.dumps(diagnostics[-25:])))
        connection.execute("""DELETE FROM wazuh_health_snapshots WHERE manager_id NOT IN
            (SELECT manager_id FROM wazuh_health_snapshots ORDER BY last_attempt_at DESC,manager_id LIMIT 16)""")

    def status(self):
        state, message = self.current
        row = None
        if self.client is not None:
            with self.store.connect() as connection:
                row = self._prior(connection)
        observed_at = row["observed_at"] if row else None
        payload = json.loads(row["payload"]) if row else {"agents": [], "manager_counts": None}
        if state == "connected" and (observed_at is None or
                (datetime.now(timezone.utc) - datetime.fromisoformat(observed_at)).total_seconds() > self.settings.poll_seconds * 2):
            state, message = "degraded", "The latest Wazuh agent observation is stale."
        counts = dict.fromkeys(STATUSES, 0)
        for agent in payload["agents"]:
            counts[agent["status"]] += 1
        return {"state": state, "manager_id": self.settings.manager_id, "demo": self.settings.demo, "message": message,
                "observed_at": observed_at, "last_attempt_at": row["last_attempt_at"] if row else None,
                "stale": state != "connected", "poll_seconds": self.settings.poll_seconds,
                "disconnected_after_seconds": self.settings.disconnected_after_seconds, "counts": counts,
                "agents": payload["agents"], "manager_counts": payload["manager_counts"],
                "diagnostics": json.loads(row["diagnostics"]) if row else []}
