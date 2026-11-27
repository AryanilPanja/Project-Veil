"""In-memory stand-ins for the Secret Service keyring, including the ways the real one misbehaves."""

import threading


class LockedException(Exception):  # same name as secretstorage's: matched by class name
    pass


class PromptDismissedException(Exception):
    pass


class SecretServiceNotAvailableException(Exception):
    pass


class MemoryKeyring:
    """A dict-backed keyring that records every call."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}
        self.calls: list[str] = []

    def get_password(self, service: str, username: str) -> str | None:
        self.calls.append("get")
        return self.items.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.calls.append("set")
        self.items[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.calls.append("delete")
        del self.items[(service, username)]


class FailingKeyring(MemoryKeyring):
    """Raises `error` from the named operations."""

    def __init__(self, error: BaseException, on: frozenset[str] = frozenset({"get", "set"})):
        super().__init__()
        self.error = error
        self.on = on

    def get_password(self, service, username):
        if "get" in self.on:
            self.calls.append("get")
            raise self.error
        return super().get_password(service, username)

    def set_password(self, service, username, password):
        if "set" in self.on:
            self.calls.append("set")
            raise self.error
        super().set_password(service, username, password)

    def delete_password(self, service, username):
        if "delete" in self.on:
            self.calls.append("delete")
            raise self.error
        super().delete_password(service, username)


class LossyKeyring(MemoryKeyring):
    """Accepts set_password but stores something else (or nothing): read-back must catch it."""

    def __init__(self, stored: str | None) -> None:
        super().__init__()
        self.stored = stored

    def set_password(self, service, username, password):
        self.calls.append("set")
        if self.stored is not None:
            self.items[(service, username)] = self.stored


class HangingKeyring(MemoryKeyring):
    """Blocks in the named operation until `release` is set (an unanswered unlock prompt)."""

    def __init__(self, on: str = "get") -> None:
        super().__init__()
        self.on = on
        self.release = threading.Event()

    def _maybe_hang(self, op: str) -> None:
        if op == self.on:
            self.release.wait(30)

    def get_password(self, service, username):
        self._maybe_hang("get")
        return super().get_password(service, username)

    def set_password(self, service, username, password):
        self._maybe_hang("set")
        super().set_password(service, username, password)
