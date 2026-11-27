"""Opt-in stage timings: `VEIL_TIMINGS=1 veil translate …` prints how long each stage took.

Value-free by construction: only stage names and milliseconds, on stderr. Off by default, and
costs one environment lookup when off.
"""

import os
import time

from veil import ui

_START = time.perf_counter()  # roughly the moment veil's own code started running


class Stages:
    def __init__(self) -> None:
        self.enabled = os.environ.get("VEIL_TIMINGS", "") not in ("", "0")
        self._last = _START
        self._marks: list[tuple[str, float]] = []

    def mark(self, stage: str) -> None:
        if not self.enabled:
            return
        now = time.perf_counter()
        self._marks.append((stage, (now - self._last) * 1000))
        self._last = now

    def report(self) -> None:
        if not self.enabled or not self._marks:
            return
        total = sum(ms for _, ms in self._marks)
        parts = ", ".join(f"{name} {ms:.0f}" for name, ms in self._marks)
        ui.err(f"veil: timings (ms): {parts}; total {total:.0f}")


STAGES = Stages()
