"""Direct HTTPS access on one explicitly selected private IPv4 network."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import os


PRIVATE_NETWORKS = tuple(map(ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


@dataclass(frozen=True)
class SharedHosting:
    host: IPv4Address
    network: IPv4Network
    port: int

    @classmethod
    def parse(cls, host: str, network: str | None, port: int):
        try:
            address = IPv4Address(host)
            subnet = IPv4Network(network or f"{host}/24", strict=bool(network))
            if (not any(subnet.subnet_of(private) for private in PRIVATE_NETWORKS)
                    or address not in subnet or address in (subnet.network_address, subnet.broadcast_address)
                    or not 1 <= port <= 65535):
                raise ValueError
        except ValueError:
            raise ValueError("Use a private host IPv4 address and its matching private subnet, such as 192.168.137.0/24.") from None
        return cls(address, subnet, port)

    @classmethod
    def from_env(cls):
        host = os.environ.get("SENTINEL_SHARED_HOST")
        if host:
            return cls.parse(host, os.environ.get("SENTINEL_SHARED_NETWORK"), int(os.environ["SENTINEL_SHARED_PORT"]))

    @property
    def authority(self):
        return str(self.host) if self.port == 443 else f"{self.host}:{self.port}"

    @property
    def origin(self):
        return f"https://{self.authority}"

    def accepts(self, scope):
        try:
            client = ip_address(scope.client.host) if scope.client else None
        except ValueError:
            return False
        return (client is not None and client in self.network and scope.url.scheme in {"https", "wss"}
                and scope.headers.getlist("host") == [self.authority])


def owner_operation(method, path):
    if method in {"GET", "HEAD"}:
        return (path.startswith(("/api/live/", "/api/collect/"))
                or (path.startswith("/api/agents/") and path.endswith("/profile")))
    if path in {"/api/ask"} or path.startswith(("/api/analysis/", "/api/findings/")):
        return False
    if path in {"/api/uploads"} or (path.startswith("/api/changes/") and path.endswith("/recovery")):
        return False
    if path == "/api/wazuh/tools/nmap/start" or path.startswith("/api/wazuh/tools/nmap/stop/"):
        return False
    if path.startswith("/api/agents/") and path.endswith("/save"):
        return False
    return True
