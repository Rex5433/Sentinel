"""Short-lived password transport for the Live Logs sign-in dialog."""

from .ssh_collection import MAX_BYTES, TIMEOUT_SECONDS
from .ssh_transport import LIVE_IDLE_SECONDS, SSHSession


class PasswordSession(SSHSession):
    @classmethod
    def connect(cls, target, password):
        session = super().connect(target, password=password, connect_timeout=15, idle_timeout=LIVE_IDLE_SECONDS)
        try:
            session._read("exit 0", allow_empty=True)
        except BaseException:
            session.close()
            raise
        return session

    def _read(self, command, *, allow_empty=False):
        return self.read(command, allow_empty=allow_empty, timeout=TIMEOUT_SECONDS, max_bytes=MAX_BYTES)
