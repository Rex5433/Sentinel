"""Local evidence review, command guidance, and opt-in lab collection."""

import asyncio
from contextlib import asynccontextmanager
from hashlib import sha256
from ipaddress import ip_address
import os
import json
from pathlib import Path
import sqlite3
from time import monotonic
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi import Path as ApiPath
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StringConstraints
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sentinel.ingest import ParseInputError, parse_linux, parse_windows
from sentinel.ingest.common import MAX_INPUT_BYTES, prepare
from sentinel.ingest.pcap import parse_pcap
from sentinel.ingest.windows_jsonl import parse_windows_jsonl
from sentinel.schemas import UtcTimestamp
from .db import EvidenceStore, StorageFull
from .reports import json_report, text_report
from .auth import AuthService, LoginBusy, LoginLimited, SESSION_SECONDS
from .log_import import FILE_EXTENSIONS, detect_format
from .log_context import account_key, with_log_context
from . import network
from . import changes
from . import ssh_collection
from .live_logs import register_live_logs
from sentinel.snapshots import parse_snapshot, MAX_BYTES as SNAPSHOT_MAX_BYTES
from .analysis import (run_analysis, analysis_summary, analysis_page, analysis_detail, event_review_page,
                       finding_evidence, update_maintenance_note, AnalysisUnavailable, ImportGone)
from sentinel.features import feature_schema, schema_hash
from sentinel.detection.rules import baseline_policy, policy_hash
from sentinel.intents.router import route, HELP as INTENT_HELP, VERSION as INTENT_VERSION
from sentinel.commands.catalog import commands, command_ids, catalog_hash, VERSION as CATALOG_VERSION
from ipaddress import IPv4Address, IPv6Address

ROOT = Path(__file__).resolve().parents[1]


class MaintenanceNote(BaseModel):
    note: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class BlueTeamAccount(BaseModel):
    platform: Literal["windows", "linux"]
    host: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
    account: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


STATIC_DIR = Path(__file__).resolve().parent / "static"
UI_VERSION = "sentinel-v2-network-patterns"
FORMATS = {
    "windows-json": ({".json"}, {"application/json", "text/json"}),
    "windows-jsonl": ({".jsonl", ".ndjson", ".json"}, {"application/json", "application/x-ndjson", "text/plain"}),
    "windows-csv": ({".csv"}, {"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain"}),
    "linux-text": ({".txt", ".log"}, {"text/plain"}),
    "linux-journal-json": ({".jsonl", ".ndjson", ".json"}, {"application/json", "application/x-ndjson", "text/plain"}),
    "pcap": ({".pcap"}, {"application/vnd.tcpdump.pcap", "application/x-pcap"}),
    "snapshot": ({".json"}, {"application/json", "text/json"}),
}
FILE_MIME_TYPES = set().union(*(mimes for key, (_, mimes) in FORMATS.items() if key != "snapshot"))
UploadFormat = Literal["auto", "windows-json", "windows-jsonl", "windows-csv", "linux-text", "linux-journal-json", "pcap", "snapshot"]
UploadId = Annotated[str, Query(pattern=r"^[a-f0-9]{32}$")]
Offset = Annotated[int, Query(ge=0)]
PageSize = Annotated[int, Query(ge=1, le=100)]


def storage_directory() -> Path:
    return Path(os.environ.get("SENTINEL_STORAGE_DIR", str(ROOT / "storage"))).resolve()


def instance_id(directory: Path) -> str:
    return sha256(str(directory.resolve()).encode("utf-8")).hexdigest()[:16]


def create_app(storage_dir: Path | None = None, *, rehearsal: bool = False, lab_ssh: bool = False) -> FastAPI:
    store = EvidenceStore(storage_dir if storage_dir is not None else storage_directory())
    auth = AuthService(store)
    cookie_name = "sentinel_session_" + instance_id(store.root)
    next_ssh_pull = 0.0

    @asynccontextmanager
    async def lifespan(application):
        await run_in_threadpool(store.initialize)
        await run_in_threadpool(auth.initialize)
        try:
            yield
        finally:
            await application.state.close_live_sessions()

    application = FastAPI(title="Sentinel · Roar Cyber | Team 84", version="0.1.0", docs_url=None,
                          redoc_url=None, openapi_url=None, lifespan=lifespan)
    application.state.store = store
    application.state.auth = auth
    application.state.session_cookie_name = cookie_name
    application.state.import_lock = asyncio.Lock()
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "::1"])

    @application.middleware("http")
    async def local_only(request: Request, call_next):
        try:
            local = request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        if not local:
            return JSONResponse({"detail": "This development service accepts loopback clients only."}, status_code=403)
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                same_origin = (parsed.scheme == request.url.scheme and parsed.netloc == request.url.netloc
                               and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                same_origin = False
            if not same_origin:
                return JSONResponse({"detail": "Cross-origin requests are not allowed."}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are not allowed."}, status_code=403)
        if request.method in ("POST", "DELETE") and request.headers.get("x-sentinel-import") != "1":
            return JSONResponse({"detail": "Missing local import request header."}, status_code=403)
        public_api = {"/api/auth/status", "/api/auth/login", "/api/auth/logout"}
        protected = request.url.path.startswith("/api/") and request.url.path not in public_api
        rehearsal_page = request.url.path in ("/rehearsal", "/static/rehearsal.html")
        if rehearsal_page and not rehearsal:
            return JSONResponse({"detail": "Rehearsal mode is disabled."}, status_code=404)
        page = rehearsal_page or request.url.path in (
            "/", "/static/index.html", "/changes", "/static/changes.html",
            "/mysql", "/static/mysql.html", "/live", "/static/live.html",
        )
        request.state.user = None
        if protected or page:
            request.state.user = await run_in_threadpool(auth.current_user, request.cookies.get(cookie_name))
        if protected and request.state.user is None:
            response = JSONResponse({"detail": "Sign in to access local evidence."}, status_code=401)
        elif page and request.state.user is None:
            response = RedirectResponse("/login", status_code=303)
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @application.exception_handler(OSError)
    @application.exception_handler(sqlite3.Error)
    async def storage_error(request, exc):
        return JSONResponse({"detail": "Local storage unavailable. Check disk space and directory permissions."}, status_code=503)

    @application.exception_handler(AnalysisUnavailable)
    @application.exception_handler(ImportGone)
    async def analysis_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @application.get("/health")
    def health():
        return {"service": "team84-sentinel", "status": "ok", "phase": "deterministic_triage",
                "model_ready": False, "competition_use_enabled": False, "ui_version": UI_VERSION,
                "instance_id": instance_id(store.root), "authentication_required": True,
                "rehearsal_enabled": rehearsal, "live_collection_enabled": lab_ssh}

    @application.get("/login", response_class=FileResponse)
    def login_page():
        return FileResponse(STATIC_DIR / "login.html", media_type="text/html")

    @application.get("/api/auth/status")
    def auth_status():
        return {"configured": auth.configured()}

    @application.get("/api/auth/me")
    def me(request: Request):
        return request.state.user

    @application.post("/api/auth/login")
    async def login(request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Sign-in requires JSON.")
        data = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(data) + len(chunk) > 8192:
                        raise HTTPException(413, "Sign-in request is too large.")
                    data.extend(chunk)
        except TimeoutError as exc:
            raise HTTPException(408, "Sign-in request timed out.") from exc
        try:
            body = json.loads(data)
            if not isinstance(body, dict) or set(body) != {"username", "password"}:
                raise ValueError()
            if any(not isinstance(body[key], str) or len(body[key]) > 128 for key in ("username", "password")):
                raise ValueError()
            body["username"].encode("utf-8")
            body["password"].encode("utf-8")
        except (ValueError, UnicodeError, RecursionError):
            # Never echo submitted credentials, including validation failures.
            raise HTTPException(400, "Invalid sign-in request.") from None
        try:
            result = await run_in_threadpool(auth.login, body["username"], body["password"], request.cookies.get(cookie_name))
        except LoginBusy:
            raise HTTPException(429, "Another sign-in is in progress. Try again shortly.", headers={"Retry-After": "1"}) from None
        except LoginLimited as exc:
            raise HTTPException(429, "Too many sign-in attempts. Wait before trying again.", headers={"Retry-After": str(exc.retry_after)}) from None
        if result is None:
            raise HTTPException(401, "Incorrect username or password.")
        token, username = result
        response = JSONResponse({"username": username, "role": "owner"})
        response.set_cookie(cookie_name, token, httponly=True, samesite="strict", secure=False,
                            path="/", max_age=SESSION_SECONDS)
        return response

    @application.post("/api/auth/logout", status_code=204)
    async def logout(request: Request):
        if await run_in_threadpool(auth.current_user, request.cookies.get(cookie_name)):
            await application.state.close_live_sessions()
        await run_in_threadpool(auth.logout, request.cookies.get(cookie_name))
        response = Response(status_code=204)
        response.delete_cookie(cookie_name, path="/", httponly=True, samesite="strict")
        return response

    @application.get("/", response_class=FileResponse)
    def landing():
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @application.get("/changes", response_class=FileResponse)
    def changes_page():
        return FileResponse(STATIC_DIR / "changes.html", media_type="text/html")

    @application.get("/mysql", response_class=FileResponse)
    def mysql_page():
        return FileResponse(STATIC_DIR / "mysql.html", media_type="text/html")

    @application.get("/live", response_class=FileResponse)
    def live_page():
        return FileResponse(STATIC_DIR / "live.html", media_type="text/html")

    @application.post("/api/uploads", status_code=201)
    async def upload(request: Request, filename: Annotated[str, Query(min_length=1, max_length=255)],
                     format: UploadFormat = "auto", platform: Literal["windows", "linux"] | None = None,
                     name: Annotated[str | None, Query(max_length=80)] = None):
        if (filename in (".", "..") or not filename.strip() or any(c in filename for c in '/\\:')
                or any(ord(c) < 32 or ord(c) == 127 for c in filename)):
            raise HTTPException(400, "Use a plain filename without paths or control characters.")
        if platform and format != "auto":
            raise HTTPException(400, "Choose a log system only for automatic pasted-text imports.")
        if name is not None and (not platform or not name.strip() or any(ord(c) < 32 or ord(c) == 127 for c in name)):
            raise HTTPException(400, "Use a nonblank name without control characters for a pasted log.")
        source_file = name.strip() if name is not None else filename
        extensions, mime_types = (FILE_EXTENSIONS, FILE_MIME_TYPES) if format == "auto" else FORMATS[format]
        mime = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if Path(filename).suffix.lower() not in extensions or mime not in mime_types | {"application/octet-stream"}:
            detail = ("Choose a .json, .jsonl, .ndjson, .csv, .log, .txt or .pcap export."
                      if format == "auto" else "File extension or content type does not match the selected format.")
            raise HTTPException(415, detail)
        length = request.headers.get("content-length")
        if platform:
            maximum, size_message = 1024 * 1024, "Pasted text exceeds 1 MiB. Use file import for larger exports."
        elif format == "snapshot":
            maximum, size_message = SNAPSHOT_MAX_BYTES, "Snapshot exceeds 4 MiB."
        else:
            maximum, size_message = MAX_INPUT_BYTES, "Upload exceeds 25 MiB."
        if length is not None:
            if not length.isascii() or not length.isdecimal() or len(length) > 20:
                raise HTTPException(400, "Invalid Content-Length.")
            if int(length) > maximum:
                raise HTTPException(413, size_message)
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import is in progress. Try again shortly.")
        async with application.state.import_lock:
            chunks = bytearray()
            try:
                async with asyncio.timeout(30):
                    async for chunk in request.stream():
                        if len(chunks) + len(chunk) > maximum:
                            raise HTTPException(413, size_message)
                        chunks.extend(chunk)
            except TimeoutError as exc:
                raise HTTPException(408, "Upload timed out. Try the file again.") from exc
            data = bytes(chunks)
            if not data:
                raise HTTPException(400, "Choose a nonempty export file.")
            upload_id = uuid4().hex
            try:
                if format == "auto":
                    format = await run_in_threadpool(detect_format, data, filename, upload_id, platform)
                    if platform is None and mime not in FORMATS[format][1] | {"application/octet-stream"}:
                        raise HTTPException(415, "File content type does not match the detected export format.")
                if format == "snapshot":
                    result = await run_in_threadpool(parse_snapshot, data, source_file=filename, upload_id=upload_id)
                    empty = False
                elif format == "pcap":
                    result = await run_in_threadpool(parse_pcap, data, source_file=filename, upload_id=upload_id)
                    empty = not result.packets
                else:
                    if format == "windows-jsonl":
                        result = await run_in_threadpool(parse_windows_jsonl, data, source_file=source_file, upload_id=upload_id)
                    else:
                        parser = parse_windows if format.startswith("windows-") else parse_linux
                        file_format = format.removeprefix("windows-").removeprefix("linux-")
                        result = await run_in_threadpool(parser, data, file_format=file_format,
                                                        source_file=source_file, upload_id=upload_id)
                    empty = not result.events and not result.rejected
                if empty:
                    raise HTTPException(400, "The export contains no records.")
                return await run_in_threadpool(store.save, data, result)
            except ParseInputError as exc:
                raise HTTPException(400, str(exc)) from exc
            except StorageFull as exc:
                raise HTTPException(409, str(exc)) from exc

    @application.get("/api/uploads")
    def uploads(offset: Offset = 0, limit: PageSize = 50):
        return store.uploads(offset, limit)

    @application.get("/api/collect/linux/status")
    def linux_collection_status():
        if not lab_ssh:
            return {"enabled": False}
        try:
            host, _, port, _ = ssh_collection.lab_target(store.root)
            options = ssh_collection.live_options(store.root)
            if options["authentication"] == "password":
                return {"enabled": True, "ready": False, "detail": "Open Live logs for SSH password connections."}
            if options["platform"] == "windows":
                return {"enabled": True, "ready": False, "detail": "Open Live logs to collect Windows event logs."}
        except ssh_collection.CollectionError as exc:
            return {"enabled": True, "ready": False, "detail": str(exc)}
        return {"enabled": True, "ready": True, "host": host, "port": port,
                "max_records": ssh_collection.MAX_RECORDS}

    @application.post("/api/collect/linux", status_code=201)
    async def collect_linux(host: Annotated[str | None, Query(max_length=253)] = None,
                            port: Annotated[int | None, Query(ge=1, le=65535)] = None):
        nonlocal next_ssh_pull
        if not lab_ssh:
            raise HTTPException(404, "Lab SSH collection is disabled.")

        def collect_import(target):
            target_host, _, target_port, _ = target
            try:
                data = ssh_collection.collect_journal(*target)
                result = parse_linux(data, file_format="journal-json", source_file=f"ssh-{target_host}-{target_port}.jsonl",
                                     upload_id=uuid4().hex)
            except (ssh_collection.CollectionError, ParseInputError) as exc:
                raise HTTPException(502, str(exc)) from exc
            if not result.events or len(result.events) + len(result.rejected) > ssh_collection.MAX_RECORDS:
                raise HTTPException(502, "SSH output did not contain a supported, bounded journal export.")
            try:
                return store.save(data, result)
            except StorageFull as exc:
                raise HTTPException(409, str(exc)) from exc

        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import is in progress. Try again shortly.")
        async with application.state.import_lock:
            try:
                target = await run_in_threadpool(ssh_collection.lab_target, store.root)
                options = await run_in_threadpool(ssh_collection.live_options, store.root)
                if options["authentication"] == "password":
                    raise HTTPException(409, "Open Live logs for SSH password connections.")
                if options["platform"] == "windows":
                    raise HTTPException(409, "Open Live logs to collect Windows event logs.")
            except ssh_collection.CollectionError as exc:
                raise HTTPException(503, str(exc)) from exc
            if (host, port) != (target[0], target[2]):
                raise HTTPException(409, "The configured SSH destination changed. Reload before collecting.")
            now = monotonic()
            if now < next_ssh_pull:
                raise HTTPException(429, "Wait at least five seconds between lab SSH pulls.",
                                    headers={"Retry-After": "5"})
            next_ssh_pull = now + 5
            return await run_in_threadpool(collect_import, target)

    @application.get("/api/uploads/{upload_id}")
    def upload_details(upload_id: str):
        item = store.get(upload_id)
        if item is None:
            raise HTTPException(404, "Import not found.")
        return item

    @application.get("/api/uploads/{upload_id}/text")
    def editable_log(upload_id: str):
        item = import_item(upload_id)
        with store.blob_path(upload_id).open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise HTTPException(413, "In-app editing supports logs up to 1 MiB. Edit a separate export and import it for larger logs.")
        if sha256(data).hexdigest() != item["sha256"]:
            raise HTTPException(409, "The saved bytes no longer match the import hash. Reimport the original export.")
        try:
            text, _ = prepare(data, source_file=item["filename"], upload_id=upload_id, parser=item["format"])
        except ParseInputError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"filename": item["filename"], "platform": "windows" if item["format"].startswith("windows-") else "linux", "text": text}

    @application.get("/api/events")
    def events(upload_id: UploadId, offset: Offset = 0, limit: PageSize = 25, include_flags: bool = False):
        item = import_item(upload_id)
        page = event_review_page(store, item, offset, limit) if include_flags else store.records(upload_id, "events", offset, limit)
        return with_log_context(store, page)

    @application.get("/api/blue-team/accounts")
    def blue_team_accounts():
        with store.connect() as connection:
            return {"items": [dict(row) for row in connection.execute(
                "SELECT id,platform,host,account FROM blue_team_accounts ORDER BY platform,host,account",
            )]}

    @application.post("/api/blue-team/accounts", status_code=204)
    def add_blue_team_account(body: BlueTeamAccount):
        try:
            key = account_key(body.platform, body.host, body.account)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        with store.connect() as connection:
            connection.execute(
                "INSERT INTO blue_team_accounts(platform,host,account) VALUES (?,?,?) "
                "ON CONFLICT(platform,host,account) DO NOTHING", key,
            )
        return Response(status_code=204)

    @application.delete("/api/blue-team/accounts/{account_id}", status_code=204)
    def remove_blue_team_account(account_id: Annotated[int, ApiPath(ge=1, le=2**63 - 1)]):
        with store.connect() as connection:
            if not connection.execute("DELETE FROM blue_team_accounts WHERE id=?", (account_id,)).rowcount:
                raise HTTPException(404, "Roster entry not found.")
        return Response(status_code=204)

    @application.get("/api/uploads/{upload_id}/rejected")
    def rejected(upload_id: str, offset: Offset = 0, limit: PageSize = 25):
        import_item(upload_id)
        return store.records(upload_id, "rejected", offset, limit)

    @application.delete("/api/uploads/{upload_id}", status_code=204)
    def delete_upload(upload_id: str):
        if not store.delete(upload_id):
            raise HTTPException(404, "Import not found.")
        return Response(status_code=204)

    @application.get("/api/timeline")
    def timeline(offset: Offset = 0, limit: PageSize = 25,
                 upload_id: Annotated[str | None, Query(pattern=r"^[a-f0-9]{32}$")] = None,
                 finding_id: Annotated[str | None, Query(pattern=r"^[a-f0-9]{64}$")] = None,
                 host: Annotated[str | None, Query(max_length=255)] = None,
                 platform: Literal["windows", "linux"] | None = None,
                 event_type: Annotated[str | None, Query(max_length=255)] = None,
                 source: Annotated[str | None, Query(max_length=255)] = None,
                 actor: Annotated[str | None, Query(max_length=255)] = None,
                 source_ip: IPv4Address | IPv6Address | None = None,
                 windows_event_id: Annotated[int | None, Query(ge=0, le=65535)] = None,
                 service: Annotated[str | None, Query(max_length=255)] = None,
                 start: UtcTimestamp | None = None, end: UtcTimestamp | None = None):
        if start is not None and end is not None and start > end:
            raise HTTPException(400, "Start time must be before or equal to end time.")
        evidence_ids = None
        if finding_id is not None:
            if upload_id is None:
                raise HTTPException(400, "Select the finding's source import.")
            entry = analysis_detail(store, import_item(upload_id), "findings", finding_id)
            if entry is None:
                raise HTTPException(404, "Finding not found for this import.")
            evidence_ids = entry["finding"]["evidence_event_ids"]
        if upload_id is not None:
            item = store.get(upload_id)
            if item and item["format"] in ("pcap", "snapshot"):
                raise HTTPException(400, "Use Network or Changes views for this import; the timeline contains log events.")
        page = store.timeline(offset, limit, upload_id=upload_id, host=host, platform=platform,
                              event_type=event_type, source=source, start=start, end=end, actor=actor,
                              source_ip=str(source_ip) if source_ip is not None else None,
                              windows_event_id=windows_event_id, service=service, evidence_ids=evidence_ids)
        return with_log_context(store, page)

    @application.get("/api/uploads/{upload_id}/overview")
    def import_overview(upload_id: str):
        import_item(upload_id)
        result = store.overview(upload_id)
        if result is None:
            raise HTTPException(404, "Import not found.")
        return result

    @application.get("/api/intents")
    def intent_help():
        return INTENT_HELP

    @application.get("/api/commands")
    def command_catalog(platform: Literal["windows", "linux"] | None = None,
                        category: Literal["authentication", "services", "processes", "network", "users", "log_collection"] | None = None,
                        q: Annotated[str, Query(max_length=128)] = ""):
        items = commands(platform=platform, category=category, q=q)
        return {"version": CATALOG_VERSION, "sha256": catalog_hash(), "items": items, "total": len(items)}

    @application.get("/api/commands/{command_id}")
    def command_detail(command_id: str):
        item = next((entry for entry in commands() if entry["id"] == command_id), None)
        if item is None:
            raise HTTPException(404, "Reference command not found.")
        return {"version": CATALOG_VERSION, "sha256": catalog_hash(), "item": item}

    @application.post("/api/ask")
    async def ask(request: Request):
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Investigation requests require JSON.")
        data = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(data) + len(chunk) > 4096:
                        raise HTTPException(413, "Investigation request is too large.")
                    data.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, "Investigation request timed out.") from None
        try:
            body = json.loads(data)
            if not isinstance(body, dict) or "query" not in body or set(body) - {"query", "upload_id", "offset", "limit"}:
                raise ValueError()
            query = body["query"]
            if not isinstance(query, str) or not 1 <= len(query) <= 512:
                raise ValueError()
            query.encode("utf-8")
            upload_id = body.get("upload_id")
            if upload_id is not None and (not isinstance(upload_id, str) or len(upload_id) != 32 or any(c not in "0123456789abcdef" for c in upload_id)):
                raise ValueError()
            offset, limit = body.get("offset", 0), body.get("limit", 25)
            if type(offset) is not int or not 0 <= offset <= 2**31 - 1 or type(limit) is not int or not 1 <= limit <= 100:
                raise ValueError()
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(400, "Invalid investigation request. Use query text, an optional import ID, offset >= 0, and limit 1-100.") from None
        if upload_id is not None:
            await run_in_threadpool(import_item, upload_id)
        intent = route(query)
        common = {"version": INTENT_VERSION, "method": "deterministic", "model_ready": False,
                  "competition_use_enabled": False, "scope": {"upload_id": upload_id,
                  "description": "Selected log import" if upload_id else "All saved log imports"}}
        if intent is None:
            return {**common, "supported": False, "intent": None, "items": [], "total": None,
                    "message": "Unsupported request. Choose a supported example; no search or command was run.",
                    "help": INTENT_HELP, "command_ids": []}
        def search_logs():
            return with_log_context(store, store.timeline(offset, limit, upload_id=upload_id, **intent.filters))

        result = await run_in_threadpool(search_logs)
        return {**common, **result, "supported": True, "intent": intent.name,
                "applied_filters": intent.filters,
                "message": f"{result['total']} matching parsed records. No threat verdict is inferred; missing/unparsed evidence and duplicate exports limit coverage.",
                "command_ids": command_ids(intent.category, intent.filters.get("platform")) if intent.category else []}

    @application.get("/api/reports/{upload_id}")
    def report(upload_id: str, format: Literal["json", "text"] = "json"):
        item = store.get(upload_id)
        if item is None:
            raise HTTPException(404, "Import not found.")
        extension = "json" if format == "json" else "txt"
        if item["format"] == "snapshot":
            raise HTTPException(400, "Use a Changes report with a baseline and current snapshot pair.")
        generator = json_report if format == "json" else text_report
        if item["format"] == "pcap":
            generator = network.json_report if format == "json" else network.text_report
        return StreamingResponse(generator(store, item), media_type="application/json" if format == "json" else "text/plain",
                                 headers={"Content-Disposition": f'attachment; filename="sentinel-{upload_id}.{extension}"'})

    def import_item(upload_id: str) -> dict:
        item = store.get(upload_id)
        if item is None:
            raise HTTPException(404, "Import not found.")
        if item["format"] == "pcap":
            raise HTTPException(400, "PCAP uses network views; log queries, event windows, and authentication rules do not apply.")
        if item["format"] == "snapshot":
            raise HTTPException(400, "Snapshot imports use the Changes page, not log analysis.")
        return item

    @application.get("/api/snapshots")
    def snapshot_list():
        return changes.snapshots(store)

    @application.get("/api/changes")
    def snapshot_changes(baseline_id: UploadId, current_id: UploadId, offset: Offset = 0, limit: PageSize = 25,
                         category: Literal["services", "files", "packages", "users", "firewall"] | None = None,
                         status: Literal["added", "removed", "modified", "unverified"] | None = None):
        return changes.page(store, baseline_id, current_id, offset, limit, category, status)

    @application.get("/api/changes/{change_id}")
    def snapshot_change_detail(change_id: str, baseline_id: UploadId, current_id: UploadId):
        return changes.change_detail(store, baseline_id, current_id, change_id)

    @application.post("/api/changes/{change_id}/recovery")
    async def recovery_plan(change_id: str, request: Request, baseline_id: UploadId, current_id: UploadId):
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "Recovery review requires JSON.")
        data = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(data) + len(chunk) > 256:
                        raise HTTPException(413, "Recovery review request is too large.")
                    data.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, "Recovery review timed out.") from None
        try:
            body = json.loads(data)
            if not isinstance(body, dict) or set(body) != {"baseline_trusted"} or body["baseline_trusted"] is not True:
                raise ValueError()
        except (ValueError, RecursionError):
            raise HTTPException(400, "Explicitly confirm that you reviewed and trust this baseline before generating a recovery script.") from None
        return await run_in_threadpool(changes.change_detail, store, baseline_id, current_id, change_id, True)

    @application.get("/api/change-report")
    def change_report(baseline_id: UploadId, current_id: UploadId, format: Literal["json", "text"] = "json"):
        generator = changes.report(store, baseline_id, current_id, format)
        extension = "json" if format == "json" else "txt"
        return StreamingResponse(generator, media_type="application/json" if format == "json" else "text/plain",
                                 headers={"Content-Disposition": f'attachment; filename="sentinel-changes-{baseline_id}-{current_id}.{extension}"'})

    def capture_item(upload_id):
        item = store.get(upload_id)
        if item is None:
            raise HTTPException(404, "Import not found.")
        if item["format"] != "pcap":
            raise HTTPException(400, "Choose a PCAP import for network views.")
        return item

    @application.get("/api/network/{upload_id}")
    def capture_summary(upload_id: str):
        result = network.summary(store, capture_item(upload_id))
        if result is None:
            raise HTTPException(503, "Stored network summary unavailable. Re-import the original capture.")
        return result

    @application.get("/api/network/{upload_id}/flows")
    def capture_flows(upload_id: str, offset: Offset = 0, limit: PageSize = 25,
                      protocol: Literal["tcp", "udp"] | None = None,
                      peer: IPv4Address | IPv6Address | None = None,
                      destination_port: Annotated[int | None, Query(ge=0, le=65535)] = None):
        capture_item(upload_id)
        return network.page(store, upload_id, "flows", offset, limit, protocol=protocol,
                            peer=str(peer) if peer is not None else None, destination_port=destination_port)

    @application.get("/api/network/{upload_id}/findings")
    def capture_findings(upload_id: str, offset: Offset = 0, limit: PageSize = 25):
        return network.findings(store, capture_item(upload_id), offset, limit)

    @application.get("/api/network/{upload_id}/findings/{finding_id}/packets")
    def capture_finding_packets(upload_id: str, finding_id: Annotated[str, ApiPath(pattern=r"^[a-f0-9]{64}$")],
                               offset: Offset = 0, limit: PageSize = 25):
        result = network.finding_packets(store, capture_item(upload_id), finding_id, offset, limit)
        if result is None:
            raise HTTPException(404, "Network finding not found in this import.")
        return result

    @application.get("/api/network/{upload_id}/packets")
    def capture_packets(upload_id: str, offset: Offset = 0, limit: PageSize = 25,
                        flow_id: Annotated[str | None, Query(pattern=r"^[a-f0-9]{64}$")] = None,
                        status: Literal["decoded", "skipped", "malformed"] | None = None):
        capture_item(upload_id)
        if flow_id is not None:
            with store.connect() as connection:
                row = connection.execute("SELECT 1 FROM network_flows WHERE upload_id=? AND flow_id=?", (upload_id, flow_id)).fetchone()
            if row is None:
                raise HTTPException(404, "Flow not found in this import.")
        return network.page(store, upload_id, "packets", offset, limit, flow_id=flow_id, status=status)

    @application.get("/api/feature-schema")
    def schema_contract():
        return {"feature_schema": feature_schema(), "feature_schema_sha256": schema_hash(),
                "baseline_policy": baseline_policy(), "baseline_policy_sha256": policy_hash()}

    @application.get("/api/analysis/{upload_id}")
    def analysis_status(upload_id: str):
        return analysis_summary(store, import_item(upload_id))

    @application.post("/api/analysis/{upload_id}")
    async def analyze_import(upload_id: str):
        item = await run_in_threadpool(import_item, upload_id)
        if application.state.import_lock.locked():
            raise HTTPException(409, "Another import or analysis is in progress. Try again shortly.")
        async with application.state.import_lock:
            try:
                return await run_in_threadpool(run_analysis, store, item)
            except ValueError as exc:
                if isinstance(exc, ImportGone):
                    raise
                raise HTTPException(400, "Normalized records cannot be analyzed consistently. Re-import the original export.") from None

    @application.get("/api/features")
    def features(upload_id: UploadId, offset: Offset = 0, limit: PageSize = 25):
        return analysis_page(store, import_item(upload_id), "features", offset, limit)

    @application.get("/api/features/{window_id}")
    def feature_detail(window_id: str, upload_id: UploadId):
        value = analysis_detail(store, import_item(upload_id), "features", window_id)
        if value is None:
            raise HTTPException(404, "Feature window not found.")
        return value

    @application.get("/api/findings")
    def findings(upload_id: UploadId, offset: Offset = 0, limit: PageSize = 25):
        return analysis_page(store, import_item(upload_id), "findings", offset, limit)

    @application.get("/api/findings/{finding_id}")
    def finding_detail(finding_id: str, upload_id: UploadId):
        item = import_item(upload_id)
        value = analysis_detail(store, item, "findings", finding_id)
        if value is None:
            raise HTTPException(404, "Finding not found.")
        window = analysis_detail(store, item, "features", value["window_id"]) if value["window_id"] else None
        category = ("network" if value["finding"]["activity_class"] == "network_activity_anomaly" else
                    "processes" if value.get("rule_version") else "authentication")
        platform = window["platform"] if window else value.get("platform")
        return {**value, "window": window, "source": item,
                "manual_check_command_ids": command_ids(category, platform)}

    @application.get("/api/findings/{finding_id}/events")
    def finding_events(finding_id: str, upload_id: UploadId, offset: Offset = 0, limit: PageSize = 25):
        value = finding_evidence(store, import_item(upload_id), finding_id, offset, limit)
        if value is None:
            raise HTTPException(404, "Finding not found.")
        return with_log_context(store, value)

    @application.post("/api/findings/{finding_id}/maintenance", status_code=204)
    def save_maintenance(finding_id: str, upload_id: UploadId, body: MaintenanceNote, request: Request):
        if not update_maintenance_note(store, import_item(upload_id), finding_id, request.state.user["username"], body.note):
            raise HTTPException(404, "Finding not found.")
        return Response(status_code=204)

    @application.delete("/api/findings/{finding_id}/maintenance", status_code=204)
    def remove_maintenance(finding_id: str, upload_id: UploadId, request: Request):
        if not update_maintenance_note(store, import_item(upload_id), finding_id, request.state.user["username"], None):
            raise HTTPException(404, "Finding not found.")
        return Response(status_code=204)

    if rehearsal:
        from .rehearsal import register_rehearsal
        register_rehearsal(application, store)
    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    register_live_logs(application, store, enabled=lab_ssh)
    return application


app = create_app(rehearsal=os.environ.get("SENTINEL_SYNTHETIC_REHEARSAL") == "1",
                 lab_ssh=os.environ.get("SENTINEL_ENABLE_LAB_SSH") == "1")
