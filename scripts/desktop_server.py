"""Local child server. Parent-pipe closure also stops the owned server."""
import argparse
import sys
import threading

import uvicorn


def watch_parent(stream, server):
    stream.read(1)  # Stop byte or EOF if the launcher exits unexpectedly.
    server.should_exit = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = uvicorn.Server(uvicorn.Config("app.main:app", host="127.0.0.1", port=args.port,
                                           access_log=False, timeout_graceful_shutdown=10))
    threading.Thread(target=watch_parent, args=(sys.stdin.buffer, server), daemon=True).start()
    server.run()


if __name__ == "__main__":
    main()
