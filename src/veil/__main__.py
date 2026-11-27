"""`python -m veil` entry point (#38, ADR-0027)."""

import sys

from veil.hardening import install_exception_hooks

# Before importing cli: a failure in its imports must still use veil's value-free error format.
install_exception_hooks()

from veil.cli import main  # noqa: E402 - the hooks must be installed first

sys.exit(main())
