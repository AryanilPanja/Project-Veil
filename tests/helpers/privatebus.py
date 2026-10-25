"""A private D-Bus daemon and fake services on it, so D-Bus code is tested without ever touching
the owner's session bus (clipboard history, KDE global shortcuts).
"""

import contextlib
import shutil
import subprocess
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={path}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""

# member → handler(body) returning (signature, reply body); raise LookupError for an error reply
Handler = Callable[[tuple], tuple[str | None, tuple]]


@contextlib.contextmanager
def private_bus(directory: Path) -> Iterator[str]:
    """A dbus-daemon with its own socket in `directory`; yields its address. Skips the test if
    dbus-daemon isn't installed."""
    daemon = shutil.which("dbus-daemon")
    if daemon is None:
        pytest.skip("dbus-daemon not installed")
    config = directory / "bus.conf"
    config.write_text(CONFIG.format(path=directory / "bus"), encoding="utf-8")
    proc = subprocess.Popen(
        [daemon, f"--config-file={config}", "--nofork", "--print-address"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        address = proc.stdout.readline().strip()
        assert address.startswith("unix:")
        yield address
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        proc.stdout.close()


class FakeService(threading.Thread):
    """Owns `name` on the bus and answers method calls on `interface` with `handlers`.
    Unknown members get UnknownMethod; a handler raising LookupError gets a Failed error."""

    def __init__(self, address: str, name: str, interface: str, handlers: dict[str, Handler]):
        super().__init__(daemon=True)
        from jeepney import message_bus
        from jeepney.io.blocking import open_dbus_connection

        self.interface, self.handlers = interface, handlers
        self.calls: list[tuple[str, tuple]] = []
        self.stop = threading.Event()
        self.connection = open_dbus_connection(address)
        self.connection.send_and_get_reply(message_bus.RequestName(name))

    def run(self) -> None:
        from jeepney import HeaderFields, MessageType, new_error, new_method_return

        while not self.stop.is_set():
            try:
                message = self.connection.receive(timeout=0.1)
            except TimeoutError:
                continue
            except OSError:
                return
            header = message.header
            if header.message_type is not MessageType.method_call:
                continue
            if header.fields.get(HeaderFields.interface) != self.interface:
                continue
            member = header.fields.get(HeaderFields.member)
            self.calls.append((member, message.body))
            handler = self.handlers.get(member)
            if handler is None:
                reply = new_error(message, "org.freedesktop.DBus.Error.UnknownMethod")
            else:
                try:
                    signature, body = handler(message.body)
                    reply = new_method_return(message, signature, body)
                except LookupError:
                    reply = new_error(message, "org.freedesktop.DBus.Error.Failed")
            self.connection.send(reply)

    def close(self) -> None:
        self.stop.set()
        self.join(timeout=2)
        self.connection.close()


@contextlib.contextmanager
def fake_service(
    address: str, name: str, interface: str, handlers: dict[str, Handler]
) -> Iterator[FakeService]:
    service = FakeService(address, name, interface, handlers)
    service.start()
    try:
        yield service
    finally:
        service.close()
