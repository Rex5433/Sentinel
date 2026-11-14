"""Authenticated Wazuh SSH, dashboard link, and remote scanner routes."""

import asyncio
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .agent_manager import body
from .nmap_scanner import NmapScanner, ScanInput, ScanTarget
from .ssh_transport import SSHFailure
from .wazuh_ssh import ConnectionInput, DashboardInput, HostKeyApprovalRequired, WazuhSSH


class WazuhTools:
    def __init__(self, store, integration):
        self.integration = integration
        self.ssh = WazuhSSH(store)
        self.scanner = NmapScanner(store, self.ssh)
        self.lock = asyncio.Lock()

    def initialize(self):
        self.ssh.initialize()
        self.scanner.initialize()

    async def monitor(self):
        # Preserve the existing environment-configured Wazuh evidence pipeline.
        health = self.integration.health
        while health.client:
            await self.refresh_manager()
            await asyncio.sleep(self.integration.settings.poll_seconds)

    async def refresh_manager(self):
        await run_in_threadpool(self.integration.health.refresh)

    def register(self, app):
        @app.get("/api/wazuh/tools")
        async def settings(request: Request):
            result = await run_in_threadpool(self.ssh.public)
            if app.state.shared and request.state.user["role"] == "teammate":
                profile = result["profile"]
                ready = bool(profile and (profile["authentication"] == "key" or result["password_available"]))
                dashboard = result["dashboard_url"]
                if urlsplit(dashboard).hostname in {"127.0.0.1", "localhost", "::1"}:
                    dashboard = None
                return {"scanner_ready": ready, "dashboard_url": dashboard,
                        "status": {key: result["status"][key] for key in ("state", "version") if key in result["status"]}}
            return result

        @app.post("/api/wazuh/tools/connection/reconnect")
        async def reconnect():
            async with self.lock:
                profile, protected = await run_in_threadpool(self.ssh.saved)
                if profile:
                    try:
                        password = await run_in_threadpool(self.ssh.saved_password, protected)
                        status, key = await run_in_threadpool(self.ssh.probe, profile, password)
                        await run_in_threadpool(self.ssh.remember, profile, password, key, status, save=False)
                    except (SSHFailure, ValueError) as exc:
                        self.ssh.report(self.ssh.revision, {"state": getattr(exc, "kind", "authentication"), "message": str(exc)})
                return await run_in_threadpool(self.ssh.public)

        @app.post("/api/wazuh/tools/connection/{operation}")
        async def connection(operation: str, request: Request):
            if operation not in {"save", "test"}:
                raise HTTPException(404, "SSH operation not found.")
            form = await body(request, ConnectionInput)
            async with self.lock:
                profile = None
                try:
                    profile, password = await run_in_threadpool(self.ssh.prepare, form)
                    status, key = await run_in_threadpool(self.ssh.probe, profile, password, interactive=True, approval=form.approval)
                    await run_in_threadpool(self.ssh.remember, profile, password, key, status, save=operation == "save")
                    if operation == "save":
                        return await run_in_threadpool(self.ssh.public)
                    return status
                except HostKeyApprovalRequired as exc:
                    raise HTTPException(409, exc.details) from None
                except SSHFailure as exc:
                    status = {"state": exc.kind, "message": str(exc)}
                    if profile is not None and self.ssh.is_saved(profile, (await run_in_threadpool(self.ssh.saved))[0]):
                        self.ssh.report(self.ssh.revision, status)
                    raise HTTPException(502, status) from None
                except ValueError as exc:
                    raise HTTPException(400, str(exc)) from None

        @app.post("/api/wazuh/tools/dashboard")
        async def save_dashboard(request: Request):
            form = await body(request, DashboardInput)
            try:
                return {"url": await run_in_threadpool(self.ssh.save_dashboard, form.url)}
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None

        @app.get("/api/wazuh/tools/nmap")
        async def scanner_status():
            return await run_in_threadpool(self.scanner.status)

        @app.post("/api/wazuh/tools/nmap/targets", status_code=204)
        async def add_target(request: Request):
            form = await body(request, ScanTarget)
            try:
                await run_in_threadpool(self.scanner.add, form)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None

        @app.delete("/api/wazuh/tools/nmap/targets/{id}", status_code=204)
        async def remove_target(id: str):
            if not await run_in_threadpool(self.scanner.remove, id):
                raise HTTPException(404, "Authorized target not found.")

        @app.post("/api/wazuh/tools/nmap/start", status_code=202)
        async def start_scan(request: Request):
            form = await body(request, ScanInput)
            async with self.lock:
                try:
                    return await run_in_threadpool(self.scanner.start, form)
                except ValueError as exc:
                    raise HTTPException(400, str(exc)) from None

        @app.post("/api/wazuh/tools/nmap/stop/{run_id}", status_code=204)
        async def stop_scan(run_id: str):
            if not await run_in_threadpool(self.scanner.stop, run_id):
                raise HTTPException(409, "That scan is no longer running.")
