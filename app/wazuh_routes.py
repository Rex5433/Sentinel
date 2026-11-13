"""Operator-facing Wazuh status and evidence for the existing owner dashboard."""

import json
import os
import re
from typing import Annotated

from fastapi import HTTPException, Query
from starlette.concurrency import run_in_threadpool

from . import wazuh_events, wazuh_receiver
from .ssh_collection import HOST
from .wazuh_health import WazuhHealth


def ssh_mapping(raw):
    if not raw:
        return {}
    try:
        if len(raw) > 8192:
            raise ValueError()
        data = json.loads(raw)
        if not isinstance(data, dict) or len(data) > 64:
            raise ValueError()
        result = {}
        for agent, target in data.items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", agent) or not isinstance(target, dict):
                raise ValueError()
            host, port = target.get("host"), target.get("port", 22)
            if (not isinstance(host, str) or not HOST.fullmatch(host)
                    or type(port) is not int or not 1 <= port <= 65535):
                raise ValueError()
            result[agent] = host.lower(), port
        return result
    except (ValueError, TypeError, RecursionError):
        return None


class WazuhIntegration:
    def __init__(self, store, settings, client=None):
        self.store = store
        self.settings = settings
        self.health = WazuhHealth(store, settings, client=client)
        self.retained_browser_evidence = False
        self.ssh_map = ssh_mapping(os.environ.get("SENTINEL_WAZUH_SSH_MAP"))

    @property
    def scope(self):
        return self.settings.manager_id if self.settings.enabled or self.retained_browser_evidence else None

    def initialize(self):
        wazuh_events.initialize(self.store)
        wazuh_receiver.initialize_delivery(self.store)
        self.health.initialize()
        with self.store.connect() as db:
            # Keep past V5 browser imports visible without loading legacy credentials or settings.
            self.retained_browser_evidence = bool(db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='wazuh_connections'"
            ).fetchone())
        if self.settings.demo:
            alert = {
                "id": "sentinel-demo-20261111",
                "timestamp": "2026-11-11T12:00:00+00:00",
                "agent": {"id": "001", "name": "demo-linux", "ip": "192.0.2.21"},
                "rule": {"id": "100001", "level": 10, "description": "Demo repeated authentication failures",
                         "groups": ["authentication_failed"]},
                "full_log": "Synthetic Wazuh example for the Sentinel dashboard.",
            }
            wazuh_events.save_event(self.store, wazuh_events.normalize_alert(self.scope, alert))

    def enrich(self, rows, observations):
        # Matches require an explicit mapping. The alert's own name/IP cannot establish identity.
        results = []
        for row in rows:
            target = (self.ssh_map or {}).get(row.get("agent_id")) if not self.settings.demo else None
            state, stamp = observations.get(target, ("unknown", None))
            results.append(row | {"ssh_status": state, "ssh_observed_at": stamp,
                                  "ssh_host": target[0] if target else None})
        return results

    def status(self):
        view = self.health.status()
        transitions = []
        delivery = None
        if self.scope:
            for kind in ("agent_disconnected", "agent_recovered"):
                transitions.extend(wazuh_events.page_events(self.store, manager_id=self.scope, event_type=kind, limit=10)["items"])
            transitions.sort(key=lambda row: (row["timestamp"], row["id"]), reverse=True)
            delivery = wazuh_receiver.delivery_status(self.store, self.scope)
        return view | {"transitions": transitions[:10], "alert_ingest_enabled": wazuh_receiver.ready(self.settings),
                       "delivery": delivery, "ssh_mapping_invalid": self.ssh_map is None}

    def register(self, application):
        @application.get("/api/wazuh/status")
        async def status():
            view = await run_in_threadpool(self.status)
            observations = application.state.live_source_health()
            view["agents"] = self.enrich(view["agents"], observations)
            view["transitions"] = self.enrich(view["transitions"], observations)
            return view

        @application.get("/api/wazuh/alerts")
        async def alerts(offset: Annotated[int, Query(ge=0, le=2**31 - 1)] = 0,
                         limit: Annotated[int, Query(ge=1, le=100)] = 25):
            if not self.scope:
                return {"items": [], "total": 0, "offset": offset, "limit": limit}
            result = await run_in_threadpool(wazuh_events.page_events, self.store, manager_id=self.scope,
                                             event_type="security_alert", offset=offset, limit=limit)
            result["items"] = self.enrich(result["items"], application.state.live_source_health())
            return result

        @application.get("/api/wazuh/events/{event_id}")
        async def event(event_id: str):
            if not self.scope or not re.fullmatch(r"[a-f0-9]{64}", event_id):
                raise HTTPException(404, "Wazuh evidence not found.")
            result = await run_in_threadpool(wazuh_events.read_event, self.store, event_id, manager_id=self.scope)
            if not result:
                raise HTTPException(404, "Wazuh evidence not found.")
            return self.enrich([result], application.state.live_source_health())[0]
