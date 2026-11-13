"""Send one Wazuh JSON fixture or alert using the receiver's trusted TLS certificate."""

import argparse
import os
from pathlib import Path
from ipaddress import IPv4Address, IPv4Network
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request

INGEST_PATH = "/api/wazuh/ingest"
MAX_BODY = 64 * 1024
TOKEN = re.compile(r"[A-Za-z0-9._~-]{32,128}")
PRIVATE_NETWORKS = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alert", type=Path, help="JSON file with one alert object")
    parser.add_argument("--url", required=True, help="Private HTTPS receiver URL ending in /api/wazuh/ingest")
    parser.add_argument("--ca", required=True, type=Path, help="Trusted receiver CA certificate")
    args = parser.parse_args()
    token = os.environ.get("SENTINEL_WAZUH_ALERT_INGEST_TOKEN", "")
    if not TOKEN.fullmatch(token):
        parser.error("Set the dedicated alert delivery token in the process environment.")
    try:
        url = urlsplit(args.url)
        if (url.scheme != "https" or not url.hostname or url.path != INGEST_PATH or url.query or url.fragment
                or url.username is not None or url.password is not None or re.search(r"\s", args.url)):
            raise ValueError()
        if not any(IPv4Address(url.hostname) in network for network in PRIVATE_NETWORKS):
            raise ValueError()
    except ValueError:
        parser.error("Use the exact private IPv4 HTTPS receiver URL.")
    try:
        with args.alert.open("rb") as stream:
            body = stream.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            parser.error("Send one JSON alert up to 64 KiB.")
        context = ssl.create_default_context(cafile=str(args.ca))
        opener = build_opener(ProxyHandler({}), RejectRedirect(), HTTPSHandler(context=context))
        request = Request(args.url, data=body, method="POST",
                          headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
        with opener.open(request, timeout=10) as response:
            if response.status not in (200, 201):
                return 1
            print("Alert accepted." if response.status == 201 else "Alert already recorded.")
            return 0
    except HTTPError as exc:
        print(f"Delivery returned HTTP {exc.code}.")
    except (OSError, ValueError, URLError):
        print("Delivery failed. Check the private route, receiver, and certificate.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
