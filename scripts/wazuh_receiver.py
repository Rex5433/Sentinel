"""Start only the TLS-protected VM alert receiver on an explicit private interface."""

import argparse
import os
from pathlib import Path

import uvicorn

from app.db import EvidenceStore
from app.wazuh_health import WazuhSettings
from app.wazuh_receiver import create_receiver, private_ip, ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="Windows VM-facing IPv4 address")
    parser.add_argument("--peer", required=True, help="Ubuntu VM source IPv4 address as seen by Windows")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--cert", type=Path, required=True, help="TLS certificate and chain")
    parser.add_argument("--key", type=Path, required=True, help="TLS private key")
    args = parser.parse_args()
    settings = WazuhSettings.from_env()
    if not ready(settings):
        parser.error("Enable live Wazuh alert delivery and configure its dedicated bearer token.")
    if not 1 <= args.port <= 65535 or not args.cert.is_file() or not args.key.is_file():
        parser.error("Provide a valid port and existing TLS certificate and key files.")
    root = Path(os.environ.get("SENTINEL_STORAGE_DIR", Path(__file__).resolve().parents[1] / "storage"))
    try:
        host = private_ip(args.bind)
        application = create_receiver(EvidenceStore(root), settings, host, args.peer)
    except ValueError as exc:
        parser.error(str(exc))
    uvicorn.run(application, host=host, port=args.port, ssl_certfile=str(args.cert), ssl_keyfile=str(args.key),
                proxy_headers=False, access_log=False, limit_concurrency=8, timeout_keep_alive=5)


if __name__ == "__main__":
    main()
