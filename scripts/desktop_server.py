"""Local child server. Parent-pipe closure also stops the owned server."""
import argparse
import sys
import threading
import os

import uvicorn


def watch_parent(stream, server):
    stream.read(1)  # Stop byte or EOF if the launcher exits unexpectedly.
    server.should_exit = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ssl-certfile")
    parser.add_argument("--ssl-keyfile")
    args = parser.parse_args()
    host = os.environ.get("SENTINEL_SHARED_HOST") or "127.0.0.1"
    if host != "127.0.0.1" and not (args.ssl_certfile and args.ssl_keyfile):
        parser.error("Shared hosting requires a TLS certificate and key.")
    server = uvicorn.Server(uvicorn.Config("app.main:app", host=host, port=args.port, proxy_headers=False,
                                           ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile,
                                           access_log=False, timeout_graceful_shutdown=10))
    threading.Thread(target=watch_parent, args=(sys.stdin.buffer, server), daemon=True).start()
    server.run()


if __name__ == "__main__":
    main()
