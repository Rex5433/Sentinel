"""Reusable, host-key-pinned SSH transport for fixed Sentinel collectors."""

from contextlib import ExitStack
from hmac import compare_digest
from pathlib import Path
import socket
from threading import RLock, Timer
from time import monotonic, sleep

import paramiko
from cryptography.exceptions import UnsupportedAlgorithm
from paramiko.ssh_exception import IncompatiblePeer

from .ssh_collection import CollectionError, KeyAuthenticationRequired, LINUX_EMPTY_OK, MAX_BYTES, TIMEOUT_SECONDS, linux_command
from .windows_live import windows_command


LIVE_IDLE_SECONDS = 45
MAX_KEYS = 4
DEFAULT_KEYS = ("id_ed25519", "id_ecdsa", "id_rsa")
KEY_ERRORS = (OSError, EOFError, ValueError, TypeError, paramiko.SSHException, UnsupportedAlgorithm)


class SSHFailure(CollectionError):
    """Safe operator-facing diagnostics; raw remote output never appears here."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind
        self.retryable = kind in {"network", "timeout"}


class SSHKeyAuthenticationRequired(SSHFailure, KeyAuthenticationRequired):
    def __init__(self, message):
        super().__init__("authentication", message)


def _disk_key(path):
    if path.is_file() and 0 < path.stat().st_size <= MAX_BYTES:
        return paramiko.PKey.from_path(path)
    raise ValueError("Invalid key file.")


def _public_key(path):
    public_path = path if path.suffix == ".pub" else Path(str(path) + ".pub")
    with public_path.open("rb") as stream:
        text = stream.read(8193)
    if len(text) > 8192:
        raise ValueError("Invalid public key file.")
    return text.split()[:2]


def _key_candidates(identity_file, stack):
    if identity_file is not None:
        path = Path(identity_file).expanduser()
        try:
            yield _disk_key(path)
            return
        except KEY_ERRORS:
            # Match an encrypted key's public identity to a local agent signer.
            try:
                public = _public_key(path)
                agent = paramiko.Agent()
                stack.callback(agent.close)
                for key in agent.get_keys():
                    if public == [key.get_name().encode("ascii"), key.get_base64().encode("ascii")]:
                        yield key
                        return
            except KEY_ERRORS:
                pass
            raise SSHKeyAuthenticationRequired(
                "The SSH key could not be used. Select an OpenSSH private key, or load it into the local SSH agent and leave the key path blank."
            ) from None

    try:
        agent = paramiko.Agent()
    except KEY_ERRORS:
        agent = None
    if agent:
        stack.callback(agent.close)
        yield from agent.get_keys()[:MAX_KEYS]
    for name in DEFAULT_KEYS:
        try:
            yield _disk_key(Path.home() / ".ssh" / name)
        except KEY_ERRORS:
            continue


def _remaining(deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise SSHFailure("timeout", "The SSH connection timed out.")
    return remaining


def _authenticate(transport, username, identity_file, password, deadline):
    if password is not None:
        transport.auth_timeout = _remaining(deadline)
        # Avoid feeding a password to an unknown MFA or keyboard-interactive prompt.
        transport.auth_password(username, password, fallback=False)
        if transport.is_authenticated():
            return
        raise paramiko.AuthenticationException()

    seen = set()
    with ExitStack() as stack:
        for key in _key_candidates(identity_file, stack):
            fingerprint = key.asbytes()
            if fingerprint in seen:
                continue
            if len(seen) >= MAX_KEYS:
                break
            seen.add(fingerprint)
            transport.auth_timeout = _remaining(deadline)
            try:
                remaining_methods = transport.auth_publickey(username, key)
            except paramiko.AuthenticationException:
                _remaining(deadline)
                if not transport.is_active():
                    raise SSHFailure("network", "The SSH connection closed during key authentication.") from None
                continue
            if transport.is_authenticated():
                return
            if remaining_methods:
                break
    raise SSHKeyAuthenticationRequired(
        "SSH key authentication was not accepted. Check the remote account and private key, or load the key into the local SSH agent."
    )


class SSHSession:
    def __init__(self, transport, *, idle_timeout=None):
        self.transport = transport
        self.lock = RLock()
        self.timer = None
        self.idle_timeout = idle_timeout
        self.idle_generation = 0
        self.touch()

    @classmethod
    def discover_host_key(cls, host, port, *, connect_timeout=8):
        """Read an untrusted server key without sending account credentials."""
        deadline = monotonic() + connect_timeout
        try:
            with socket.create_connection((host, port), timeout=_remaining(deadline)) as sock:
                transport = paramiko.Transport(sock)
                try:
                    transport.banner_timeout = _remaining(deadline)
                    transport.start_client(timeout=_remaining(deadline))
                    _remaining(deadline)
                    return transport.get_remote_server_key()
                finally:
                    transport.close()
        except TimeoutError:
            raise SSHFailure("timeout", "The SSH connection timed out.") from None
        except IncompatiblePeer:
            raise SSHFailure("host_key", "The server has no compatible SSH host-key algorithm.") from None
        except (OSError, EOFError, paramiko.SSHException):
            _remaining(deadline)
            raise SSHFailure("network", "SSH port unreachable. Check the VM, hotspot, and port forwarding.") from None

    @classmethod
    def connect(cls, target, *, identity_file=None, password=None, connect_timeout=5, keepalive=15,
                idle_timeout=None, host_fingerprint=None, host_key_type=None, trusted_keys=None):
        host, username, port, known_hosts = target
        if connect_timeout <= 0 or keepalive < 0:
            raise SSHFailure("configuration", "Use positive SSH connection timeouts and a nonnegative keepalive.")
        deadline = monotonic() + connect_timeout
        keys = None
        if host_fingerprint is None and trusted_keys is None:
            try:
                with Path(known_hosts).open("rb") as stream:
                    pins = stream.read(MAX_BYTES + 1)
                if len(pins) > MAX_BYTES or any(line.lstrip().startswith(b"@") for line in pins.splitlines()):
                    raise ValueError("Unsupported host key pin file.")
                keys = paramiko.HostKeys(str(known_hosts)).lookup(host if port == 22 else f"[{host}]:{port}")
            except (OSError, ValueError, paramiko.SSHException):
                raise SSHFailure("host_key", "The verified SSH host key file could not be read.") from None
            if not keys:
                raise SSHFailure("host_key", "No verified host key is available for this SSH destination.")

        transport = None
        sock = None
        established = False
        try:
            sock = socket.create_connection((host, port), timeout=_remaining(deadline))
            transport = paramiko.Transport(sock)
            transport.banner_timeout = _remaining(deadline)
            if keys is not None or trusted_keys is not None or host_key_type is not None:
                security = transport.get_security_options()
                allowed = keys if keys is not None else trusted_keys if trusted_keys is not None else (host_key_type,)
                security.key_types = tuple(algorithm for algorithm in security.key_types
                                           if ("ssh-rsa" if algorithm.startswith("rsa-sha2-") else algorithm) in allowed)
                if not security.key_types:
                    raise SSHFailure("host_key", "The verified SSH host key uses an unsupported algorithm.")
            transport.start_client(timeout=_remaining(deadline))
            _remaining(deadline)
            actual = transport.get_remote_server_key()
            if trusted_keys is not None:
                matches = actual in trusted_keys.get(actual.get_name(), ())
            elif keys is not None:
                matches = keys.get(actual.get_name()) == actual
            else:
                matches = compare_digest(actual.fingerprint, host_fingerprint)
            if not matches:
                raise SSHFailure("host_key", "SSH host key does not match the verified key. Verify it before reconnecting.")
            _authenticate(transport, username, identity_file, password, deadline)
            transport.set_keepalive(keepalive)
            session = cls(transport, idle_timeout=idle_timeout)
            established = True
            return session
        except SSHFailure:
            raise
        except paramiko.AuthenticationException:
            _remaining(deadline)
            if transport is not None and not transport.is_active():
                raise SSHFailure("network", "The SSH connection closed during authentication.") from None
            raise SSHFailure("authentication",
                             "SSH password authentication failed or requires an unsupported second factor.") from None
        except IncompatiblePeer:
            raise SSHFailure("host_key", "The SSH server could not negotiate using the verified host key and supported algorithms.") from None
        except TimeoutError:
            raise SSHFailure("timeout", "The SSH connection timed out.") from None
        except (OSError, EOFError, paramiko.SSHException, ValueError):
            _remaining(deadline)
            raise SSHFailure("network", "Could not establish SSH. Check the VPN route and SSH service.") from None
        finally:
            if transport is not None:
                if transport.auth_handler is not None:
                    # Paramiko retains references to credential arguments after authentication.
                    transport.auth_handler.password = None
                    transport.auth_handler.private_key = None
                if not established:
                    transport.close()
            elif sock is not None:
                sock.close()

    @property
    def active(self):
        with self.lock:
            return self.transport is not None and self.transport.is_active() and self.transport.is_authenticated()

    def touch(self):
        with self.lock:
            if not self.active:
                self.close()
                raise SSHFailure("network", "The SSH session expired or closed. Select Connect again.")
            if self.idle_timeout is not None:
                if self.timer:
                    self.timer.cancel()
                self.idle_generation += 1
                self.timer = Timer(self.idle_timeout, self._expire_idle, args=(self.idle_generation,))
                self.timer.daemon = True
                self.timer.start()

    def _expire_idle(self, generation):
        with self.lock:
            if generation == self.idle_generation:
                self.close()

    def close(self):
        with self.lock:
            self.idle_generation += 1
            if self.timer:
                self.timer.cancel()
                self.timer = None
            if self.transport is not None:
                self.transport.close()
                self.transport = None

    def collect(self, options):
        self.touch()
        if options["platform"] == "windows":
            command = windows_command(options["channel"], options.get("offset", 0), bookmark=options.get("bookmark"))
            return self._read(command, allow_empty=True)
        channel = options.get("channel", "Security")
        return self._read(linux_command(channel, options.get("bookmark")), allow_empty=channel in LINUX_EMPTY_OK)

    def _read(self, command, *, allow_empty=False):
        return self.read(command, allow_empty=allow_empty)

    def read(self, command, *, allow_empty=True, timeout=TIMEOUT_SECONDS, max_bytes=MAX_BYTES):
        with self.lock:
            transport = self.transport
            if not self.active:
                raise SSHFailure("network", "The SSH connection closed. Reconnect to continue collecting.")
        channel = None
        timer = None
        deadline = monotonic() + timeout
        try:
            channel = transport.open_session(timeout=min(5, timeout))
            timer = Timer(max(.001, deadline - monotonic()), channel.close)
            timer.daemon = True
            timer.start()
            channel.exec_command(command)
            data, stderr = bytearray(), bytearray()
            total = 0
            while monotonic() < deadline:
                received = False
                if channel.recv_ready():
                    chunk = channel.recv(32768)
                    data.extend(chunk)
                    total += len(chunk)
                    received = True
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(32768)
                    stderr.extend(chunk[:max(0, 8192 - len(stderr))])
                    total += len(chunk)
                    received = True
                if total > max_bytes:
                    raise SSHFailure("output_limit", "SSH collector output exceeds the configured size limit.")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    if monotonic() >= deadline:
                        raise SSHFailure("timeout", "SSH log retrieval timed out.")
                    status = channel.recv_exit_status()
                    if status == -1 and not self.active:
                        raise SSHFailure("network", "The SSH connection was interrupted during collection.")
                    if status:
                        diagnostics = stderr.lower()
                        if any(value in diagnostics for value in
                               (b"permission denied", b"access is denied", b"unauthorizedaccessexception",
                                b"unauthorized operation", b"insufficient permissions")):
                            raise SSHFailure("permission", "SSH authenticated, but the account cannot read the selected log source.")
                        raise SSHFailure("command", "SSH authenticated, but the remote collector command failed. Check the platform and log read permissions.")
                    if not data.strip() and not allow_empty:
                        raise SSHFailure("command", "The SSH account returned no journal entries.")
                    return bytes(data)
                if not received:
                    sleep(.01)
            raise SSHFailure("timeout", "SSH log retrieval timed out.")
        except paramiko.ChannelException:
            raise SSHFailure("command", "SSH authenticated, but the server refused a command channel.") from None
        except (OSError, EOFError, paramiko.SSHException) as exc:
            if (isinstance(exc, TimeoutError) or monotonic() >= deadline
                    or (channel is None and str(exc) == "Timeout opening channel.")):
                raise SSHFailure("timeout", "SSH log retrieval timed out.") from None
            if self.active and channel is not None:
                raise SSHFailure("command", "SSH authenticated, but the server rejected the collector command.") from None
            raise SSHFailure("network", "The SSH connection was interrupted during collection.") from None
        finally:
            if timer:
                timer.cancel()
            if channel:
                channel.close()
