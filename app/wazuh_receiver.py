"""Separate, VM-facing Wazuh alert delivery application."""

import asyncio
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from hmac import compare_digest
from ipaddress import IPv4Address, IPv4Network
import re
import sqlite3
from time import monotonic

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import wazuh_events


INGEST_PATH = "/api/wazuh/ingest"
MAX_BODY = wazuh_events.MAX_ALERT_BYTES
REQUESTS_PER_MINUTE = 120
PRIVATE_NETWORKS = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
TOKEN = re.compile(r"[A-Za-z0-9._~-]{32,128}")


def private_ip(value):
    address = IPv4Address(value)
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("Use an explicit private IPv4 address on the VM-facing network.")
    return str(address)


def ready(settings):
    return bool(settings.enabled and not settings.demo and settings.alert_ingest_enabled
                and not settings.ingest_error and TOKEN.fullmatch(settings.alert_ingest_token or ""))


def initialize_delivery(store):
    with store.connect() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS wazuh_delivery (
            id INTEGER PRIMARY KEY, manager_id TEXT NOT NULL, observed_at TEXT NOT NULL, outcome TEXT NOT NULL
        )""")


def record_delivery(store, manager_id, outcome):
    observed = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    with store.connect() as connection:
        connection.execute("INSERT INTO wazuh_delivery(manager_id,observed_at,outcome) VALUES (?,?,?)",
                           (manager_id, observed, outcome))
        connection.execute("DELETE FROM wazuh_delivery WHERE id NOT IN "
                           "(SELECT id FROM wazuh_delivery ORDER BY id DESC LIMIT 200)")


def delivery_status(store, manager_id):
    with store.connect() as connection:
        row = connection.execute("SELECT observed_at,outcome FROM wazuh_delivery WHERE manager_id=? "
                                 "ORDER BY id DESC LIMIT 1", (manager_id,)).fetchone()
    return dict(row) if row else None


def create_receiver(store, settings, bind_ip, peer_ip):
    bind_ip, peer_ip = private_ip(bind_ip), private_ip(peer_ip)
    if bind_ip == peer_ip:
        raise ValueError("Set the Windows receiver and VM peer to different addresses.")

    @asynccontextmanager
    async def lifespan(_):
        await run_in_threadpool(store.initialize)
        await run_in_threadpool(wazuh_events.initialize, store)
        await run_in_threadpool(initialize_delivery, store)
        yield

    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=[bind_ip])
    requests = deque(maxlen=REQUESTS_PER_MINUTE)
    receiving = asyncio.Lock()

    @application.post(INGEST_PATH)
    async def ingest(request: Request):
        if not ready(settings):
            raise HTTPException(404, "Wazuh alert delivery is disabled.")
        if request.url.scheme != "https" or not request.client or request.client.host != peer_ip:
            raise HTTPException(403, "Use the configured private HTTPS path.")
        auth = request.headers.get("authorization", "")
        if len(auth) > 135 or not compare_digest(auth.encode(), f"Bearer {settings.alert_ingest_token}".encode()):
            raise HTTPException(401, "Alert delivery authentication failed.", headers={"WWW-Authenticate": "Bearer"})
        now = monotonic()
        while requests and now - requests[0] >= 60:
            requests.popleft()
        if len(requests) >= REQUESTS_PER_MINUTE or receiving.locked():
            raise HTTPException(429, "Alert receiver is busy. Retry shortly.", headers={"Retry-After": "5"})
        requests.append(now)
        async with receiving:
            try:
                raw = await read_alert(request)
                event = wazuh_events.normalize_alert(settings.manager_id, raw)
                inserted = await run_in_threadpool(wazuh_events.save_event, store, event)
            except HTTPException as exc:
                await note(settings.manager_id, f"rejected_{exc.status_code}")
                raise
            except wazuh_events.EventTooLarge:
                await note(settings.manager_id, "rejected_413")
                raise HTTPException(413, "Alert exceeds the evidence limits.") from None
            except wazuh_events.EventValidationError:
                await note(settings.manager_id, "rejected_400")
                raise HTTPException(400, "Invalid Wazuh alert.") from None
            except wazuh_events.EventConflict:
                await note(settings.manager_id, "rejected_409")
                raise HTTPException(409, "This alert identity already exists with different evidence.") from None
            except (sqlite3.Error, OSError):
                raise HTTPException(503, "Alert storage is unavailable. Retry delivery.") from None
            await note(settings.manager_id, "accepted" if inserted else "duplicate")
            return JSONResponse({"id": event["id"], "status": "accepted" if inserted else "duplicate"},
                                status_code=201 if inserted else 200, headers={"Cache-Control": "no-store"})

    async def note(manager_id, outcome):
        try:
            await run_in_threadpool(record_delivery, store, manager_id, outcome)
        except (sqlite3.Error, OSError):
            # Evidence delivery success does not depend on writing a status entry.
            pass

    return application


async def read_alert(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Send one JSON alert object.")
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdecimal() or len(length) > 20:
            raise HTTPException(400, "Invalid Content-Length.")
        if int(length) > MAX_BODY:
            raise HTTPException(413, "Alert exceeds 64 KiB.")
    body = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_BODY:
                    raise HTTPException(413, "Alert exceeds 64 KiB.")
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, "Alert delivery timed out.") from None
    return wazuh_events.decode_alert(bytes(body))
