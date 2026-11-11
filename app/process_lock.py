"""One reentrant state lock shared by the private admin and guest processes."""
import fcntl
import os
import threading
import time


class StateBusy(Exception):
    """No state was read or changed because another operation holds the lock."""


class ProcessRLock:
    def __init__(self, path, timeout=3):
        self.path = path
        self.mutex = threading.RLock()
        self.local = threading.local()
        self.timeout = timeout

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        if not self.mutex.acquire(timeout=self.timeout):
            raise StateBusy()
        try:
            depth = getattr(self.local, 'depth', 0)
            if depth == 0:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.local.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    while True:
                        try:
                            fcntl.flock(self.local.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise StateBusy()
                            time.sleep(min(0.02, max(0, deadline-time.monotonic())))
                except Exception:
                    os.close(self.local.fd)
                    raise
            self.local.depth = depth + 1
            return self
        except Exception:
            self.mutex.release()
            raise

    def __exit__(self, *args):
        self.local.depth -= 1
        if self.local.depth == 0:
            try:
                fcntl.flock(self.local.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.local.fd)
        self.mutex.release()
