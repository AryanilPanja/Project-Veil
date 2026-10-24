"""Global exit-code table for every `veil` command (ADR-0027)."""

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1  # validation errors, `audit` found real forms
    USAGE = 2  # argparse / bad invocation
    OFF = 3  # `veil status`: veil is switched off
    KEY_UNAVAILABLE = 4  # keyring locked/unavailable, identity missing
    DECRYPT_FAILED = 5  # wrong key, corrupt file, recipient mismatch, wrong passphrase
    BUSY = 6  # lock held by another process
    UNSAFE_ENVIRONMENT = 7  # no TTY for a human-only command, bad runtime dir, refused editor…
    ABORTED = 8  # the user cancelled
    INTERNAL = 70  # unexpected exception (class name only is shown)
    INTERRUPTED = 130  # SIGINT
