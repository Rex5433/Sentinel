"""Authenticated host enrollment and collection controls."""

import asyncio
import re
import sqlite3
import subprocess
from time import monotonic
from urllib.parse import quote
from uuid import uuid4

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Literal
from starlette.concurrency import run_in_threadpool

from .agent_collectors import DEFAULT_MODULES, MODULES
from .agent_manager import ActionInput, AgentInput, SaveInput, TEST_TTL, body, validate_profile
from .agent_store import MAX_AGENTS
from .analysis import run_analysis
from .ssh_collection import CollectionError
from .ssh_transport import SSHFailure


def register_agents(application, manager):
    evidence = manager.evidence

    def require_scheduler():
        if not manager.lease:
            raise HTTPException(409, "This process does not own the managed SSH scheduler for this store.")

    async def find(id):
        value = await run_in_threadpool(evidence.get, id)
        if not value:
            raise HTTPException(404, "Managed SSH host not found.")
        return value

    def view(row):
        worker = manager.workers.get(row["id"])
        status = row.get("status", "disabled")
        if not row["enabled"] or worker is None:
            status = "disabled"
        return row | {"status": status}

    @application.get("/api/agents/modules")
    async def modules():
        return {"modules": MODULES, "defaults": DEFAULT_MODULES}

    @application.get("/api/agents")
    async def agents():
        return {"items": [view(row) for row in await run_in_threadpool(evidence.list)], "limit": MAX_AGENTS}

    @application.post("/api/agents/test")
    async def test_connection(request: Request):
        require_scheduler()
        form = await body(request, AgentInput)
        values = form.model_dump(exclude={"password", "agent_id"})
        values["id"] = form.agent_id or uuid4().hex
        previous = await find(form.agent_id) if form.agent_id else None
        generation = manager.generation
        try:
            validate_profile(values)
            if not previous and any((row["host"], row["port"]) == (values["host"], values["port"])
                                    for row in await run_in_threadpool(evidence.list)):
                raise ValueError("This address and port are already enrolled.")
            password = form.password.get_secret_value() if form.password and form.authentication != "key" else None
            async with manager.slots:
                tested, fingerprints = await run_in_threadpool(manager.probe, values, password, previous)
        except SSHFailure as exc:
            raise HTTPException(400, {"kind": exc.kind, "message": str(exc)}) from None
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            message = str(exc) if isinstance(exc, ValueError) else "The local SSH trust or key file could not be read."
            raise HTTPException(400, message) from None
        if generation != manager.generation:
            raise HTTPException(409, "The local session closed during the connection test.")
        if len(manager.pending) >= MAX_AGENTS:
            manager.pending.pop(next(iter(manager.pending)))
        id = uuid4().hex
        manager.pending[id] = tested
        asyncio.get_running_loop().call_later(TEST_TTL, manager.pending.pop, id, None)
        return {"test_id": id, "platform": values["platform"], "modules": values["modules"],
                "streams": tested.streams, "fingerprints": fingerprints}

    async def save_profile(form, id=None):
        require_scheduler()
        async with manager.mutation:
            tested = manager.pending.pop(form.test_id, None)
            if tested is None or tested.expires < monotonic():
                raise HTTPException(409, "Test the connection again before saving.")
            profile = tested.profile
            existing = await run_in_threadpool(evidence.get, profile["id"])
            if (id is None and existing) or (id is not None and (id != profile["id"] or not existing)):
                raise HTTPException(409, "This connection test does not match the selected host.")
            if existing:
                await manager.stop(id)
            try:
                await run_in_threadpool(evidence.put, profile, tested.pins)
            except sqlite3.IntegrityError:
                raise HTTPException(409, "This SSH address and port are already enrolled.") from None
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
            existing_streams = await run_in_threadpool(evidence.streams, profile["id"])
            for stream in tested.streams:
                if stream["id"] not in existing_streams:
                    await run_in_threadpool(evidence.stream_status, profile["id"], stream["id"], None, stream)
            await run_in_threadpool(evidence.set_health, profile["id"], "connecting" if profile["enabled"] else "disabled")
            manager.start(profile, tested.pins, tested.password)
            return view(await run_in_threadpool(evidence.detail, profile["id"]))

    @application.post("/api/agents", status_code=201)
    async def add(request: Request):
        return await save_profile(await body(request, SaveInput))

    @application.post("/api/agents/{id}/edit")
    async def edit(id: str, request: Request):
        return await save_profile(await body(request, SaveInput), id)

    @application.get("/api/agents/{id}")
    async def detail(id: str):
        row = await run_in_threadpool(evidence.detail, id)
        if row is None:
            raise HTTPException(404, "Managed SSH host not found.")
        return view(row) | {"live_capture": await run_in_threadpool(manager.capture.status, id)}

    @application.get("/api/agents/{id}/profile")
    async def download_profile(id: str):
        profile, _, _ = await find(id)
        fields = ("name", "host", "port", "username", "platform", "authentication", "role",
                  "interval_seconds", "modules", "integrity_paths")
        document = {"version": 1, **{key: profile[key] for key in fields if key in profile}}
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]+', "-", profile["name"]).strip(" .-")[:80] or "profile"
        fallback = re.sub(r"[^A-Za-z0-9._ -]+", "-", name).strip(" .-") or "profile"
        filename = f"sentinel-host-{name}.json"
        return JSONResponse(document, headers={"Content-Disposition": (
            f'attachment; filename="sentinel-host-{fallback}.json"; filename*=UTF-8\'\'{quote(filename, safe="")}'
        ),
                                               "Cache-Control": "no-store"})

    @application.post("/api/agents/{id}/capture/{operation}")
    async def live_capture(id: str, operation: Literal["start", "stop"]):
        require_scheduler()
        async with manager.mutation:
            profile, _, _ = await find(id)
            if operation == "start":
                if id not in manager.workers:
                    raise HTTPException(409, "Connect this host before starting a live capture.")
                async with manager.import_lock:
                    await run_in_threadpool(manager.capture.start, id)
            try:
                upload_id = await manager.save_live(profile, force=True, stop=operation == "stop")
            except ValueError as exc:
                if operation == "stop":
                    raise HTTPException(409, str(exc)) from None
                upload_id = None
            return {"last_upload_id": upload_id, "live_capture": await run_in_threadpool(manager.capture.status, id)}

    @application.get("/api/agents/{id}/live")
    async def live(id: str):
        return await run_in_threadpool(evidence.live, await detail(id))

    @application.get("/api/agents/{id}/findings/{finding_id}/evidence")
    async def finding_evidence(id: str, finding_id: str):
        result = await run_in_threadpool(evidence.finding_evidence, id, finding_id)
        if result is None:
            raise HTTPException(404, "This finding is no longer in the host's recent findings.")
        return result

    @application.post("/api/agents/{id}/save", status_code=201)
    async def save_logs(id: str):
        profile, _, _ = await find(id)
        async with application.state.import_lock:
            try:
                item = await run_in_threadpool(evidence.export, id, profile["name"])
                await run_in_threadpool(run_analysis, manager.store, item)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
        return {"upload_id": item["id"]}

    @application.delete("/api/agents/{id}", status_code=204)
    async def delete(id: str):
        require_scheduler()
        async with manager.mutation:
            await find(id)
            if await run_in_threadpool(manager.capture.status, id) is not None:
                raise HTTPException(409, "Stop live capture before removing this host.")
            await manager.stop(id)
            await run_in_threadpool(evidence.remove, id)

    @application.post("/api/agents/{id}/action")
    async def action(id: str, request: Request):
        require_scheduler()
        form = await body(request, ActionInput)
        async with manager.mutation:
            profile, pins, _ = await find(id)
            worker = manager.workers.get(id)
            if form.action == "purge":
                if worker:
                    raise HTTPException(409, "Disconnect the host before clearing its retained events.")
                if await run_in_threadpool(manager.capture.status, id) is not None:
                    raise HTTPException(409, "Stop live capture before clearing retained evidence.")
                await run_in_threadpool(evidence.purge, id)
            elif form.action == "disconnect":
                await manager.stop(id)
                profile["enabled"] = False
                await run_in_threadpool(evidence.put, profile, pins)
                await run_in_threadpool(evidence.set_health, id, "disabled")
            elif form.action == "reset_gap":
                state = await run_in_threadpool(evidence.streams, id)
                previous = state.get(form.stream_id)
                if not previous or previous[1]["status"] != "gap":
                    raise HTTPException(409, "Select a collector with a paused gap.")
                await run_in_threadpool(evidence.stream_status, id, form.stream_id, None,
                                        previous[1] | {"status": "ready", "error": None,
                                                       "gap_reset": True, "observed_at": None})
                if worker:
                    worker.wake.set()
            elif form.action == "collect" and worker and not form.password:
                worker.wake.set()
            else:
                password = form.password.get_secret_value() if form.password and profile["authentication"] != "key" else None
                password = password or (worker.password if worker else None)
                if profile["authentication"] == "password" and not password:
                    raise HTTPException(400, "Enter the SSH account password for this session.")
                await manager.stop(id)
                profile["enabled"] = True
                await run_in_threadpool(evidence.put, profile, pins)
                await run_in_threadpool(evidence.set_health, id, "connecting")
                manager.start(profile, pins, password)
                manager.workers[id].wake.set()
        return await detail(id)
