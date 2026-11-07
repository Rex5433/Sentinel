"""Pinned-key, password-authenticated SSH sessions; no credential persistence."""

import socket
from threading import RLock, Timer
from time import monotonic, sleep

import paramiko

from .ssh_collection import CollectionError, COMMAND, MAX_BYTES, TIMEOUT_SECONDS
from .windows_live import windows_command


IDLE_SECONDS = 45


class PasswordSession:
    def __init__(self, transport):
        self.transport = transport
        self.lock = RLock()
        self.timer = None
        self.idle_generation = 0
        self.touch()

    @classmethod
    def connect(cls, target, password):
        host, username, port, known_hosts = target
        transport = None
        sock = None
        session = None
        completed = False
        try:
            keys = paramiko.HostKeys(str(known_hosts)).lookup(host if port == 22 else f"[{host}]:{port}")
            if not keys:
                raise CollectionError("No verified host key is available for this SSH destination.")
            sock = socket.create_connection((host, port), timeout=5)
            transport = paramiko.Transport(sock)
            transport.banner_timeout = 5
            transport.auth_timeout = 10
            security = transport.get_security_options()
            security.key_types = tuple(algorithm for algorithm in security.key_types
                                       if ("ssh-rsa" if algorithm.startswith("rsa-sha2-") else algorithm) in keys)
            transport.start_client(timeout=5)
            actual = transport.get_remote_server_key()
            if keys.get(actual.get_name()) != actual:
                raise CollectionError("SSH host key does not match the verified key. Verify it before reconnecting.")
            # Do not reuse the password as a response to unknown keyboard-interactive/MFA prompts.
            transport.auth_password(username, password, fallback=False)
            if not transport.is_authenticated():
                raise paramiko.AuthenticationException()
            session = cls(transport)
            session._read("exit 0", allow_empty=True)
            completed = True
            return session
        except paramiko.AuthenticationException:
            raise CollectionError("SSH password authentication failed or requires an unsupported second factor.") from None
        except (OSError, paramiko.SSHException, ValueError):
            raise CollectionError("Could not establish the SSH session. Check the verified host key, connectivity, and server password support.") from None
        finally:
            # Paramiko retains this argument on its auth handler after the handshake.
            # Drop that reference; Python strings do not offer guaranteed zeroization.
            if transport is not None and transport.auth_handler is not None:
                transport.auth_handler.password = None
            # Ownership transfers to the session only after authentication and the fixed probe.
            if session is not None and not completed:
                session.close()
            elif transport is not None and not completed:
                transport.close()
            elif transport is None and sock is not None:
                sock.close()

    @property
    def active(self):
        with self.lock:
            return self.transport is not None and self.transport.is_authenticated()

    def touch(self):
        with self.lock:
            if not self.active:
                self.close()
                raise CollectionError("The SSH password session expired. Select Connect to sign in again.")
            if self.timer:
                self.timer.cancel()
            self.idle_generation += 1
            self.timer = Timer(IDLE_SECONDS, self._expire_idle, args=(self.idle_generation,))
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
        return self._read(windows_command(options["channel"]) if options["platform"] == "windows" else COMMAND,
                          allow_empty=options["platform"] == "windows")

    def _read(self, command, *, allow_empty=False):
        channel = None
        timer = None
        deadline = monotonic() + TIMEOUT_SECONDS
        try:
            if not self.active:
                raise CollectionError("The SSH password session closed. Select Connect to sign in again.")
            channel = self.transport.open_session(timeout=min(5, TIMEOUT_SECONDS))
            timer = Timer(max(.01, deadline - monotonic()), channel.close)
            timer.daemon = True
            timer.start()
            channel.exec_command(command)
            data = bytearray()
            total = 0
            while monotonic() < deadline:
                received = False
                if channel.recv_ready():
                    chunk = channel.recv(32768)
                    data.extend(chunk)
                    total += len(chunk)
                    received = True
                if channel.recv_stderr_ready():
                    total += len(channel.recv_stderr(32768))
                    received = True
                if total > MAX_BYTES:
                    raise CollectionError("SSH log output exceeds 1 MiB. Export a smaller sample manually.")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    if channel.recv_exit_status() != 0:
                        raise CollectionError("SSH log retrieval failed. Check the account's event log permissions.")
                    if not data.strip() and not allow_empty:
                        raise CollectionError("The SSH account returned no journal entries.")
                    return bytes(data)
                if not received:
                    sleep(.01)
            raise CollectionError("SSH log retrieval timed out. Retry or import an export manually.")
        except (OSError, EOFError, paramiko.SSHException, AttributeError):
            raise CollectionError("The SSH session closed or timed out. Reconnect and check log read permissions.") from None
        finally:
            if timer:
                timer.cancel()
            if channel:
                channel.close()
