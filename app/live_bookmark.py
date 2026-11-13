"""Verified SSH source identity and durable live collection positions."""

from hashlib import sha256
import json
import re

from sentinel.ingest.common import load_json
from .ssh_collection import CollectionError


class BookmarkGap(CollectionError):
    pass


def bookmark_scope(target, options):
    host, account, port, known_hosts = target
    pin = sha256(known_hosts.read_bytes()).hexdigest()
    value = ["live-bookmark-v1", host, account, port, pin, options["platform"], options["channel"]]
    return sha256(json.dumps(value).encode()).hexdigest()[:32]


def read_bookmark(store, scope):
    with store.connect() as connection:
        row = connection.execute("SELECT position FROM live_bookmarks WHERE scope=?", (scope,)).fetchone()
    return row[0] if row else None


def write_bookmark(store, scope, position):
    with store.connect() as connection:
        connection.execute("INSERT INTO live_bookmarks(scope,position) VALUES (?,?) "
                           "ON CONFLICT(scope) DO UPDATE SET position=excluded.position", (scope, position))


def position_for(platform, cursor, raw):
    if platform == "linux":
        if not re.fullmatch(r"[a-zA-Z0-9=;]{1,512}", cursor):
            raise CollectionError("The source returned an invalid journal cursor.")
        return cursor
    number = load_json(raw.decode("utf-8-sig"))["RecordId"]
    if number > 2**63 - 1:
        raise CollectionError("The source returned an out-of-range Windows record number.")
    return f"{number}:{cursor}"


def after_anchor(platform, batch, position):
    if not batch or position_for(platform, *next(iter(batch.items()))) != position:
        raise BookmarkGap("The saved position is missing from this source. Export the affected interval, then restart from latest to establish a new bookmark.")
    batch.pop(next(iter(batch)))
    if platform == "windows":
        ids = [int(position.split(":", 1)[0])]
        ids.extend(load_json(line.decode("utf-8-sig"))["RecordId"] for line in batch.values())
        if any(new <= old for old, new in zip(ids, ids[1:])):
            raise CollectionError("Windows returned a page with out-of-order or repeated record numbers.")
    return batch
