"""
detectors.py provides Detector implementations
"""

import asyncio
import time
from collections import deque
from pathlib import Path
from typing import ClassVar

from pdf import dead_zone_pdf, minimal_pdf
from simulation import Detector, Log, Result
from syscall import Op, SysCall, TraceEvent


class WriteBurstDetector(Detector):
    "Detects when `threshold` writes happen within `window` seconds"

    threshold: int
    window: float

    times: deque[float]
    hit: asyncio.Event

    def __init__(self, threshold: int = 10, window: float = 1.0) -> None:
        self.threshold = threshold
        self.window = window

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.times = deque()
        self.hit = asyncio.Event()
        log(f"threshold={self.threshold} writes, window={self.window}s")

    def on_event(self, event: TraceEvent) -> None:
        if event.op != Op.WRITE:
            return

        self.times.append(event.ts)
        while event.ts - self.times[0] > self.window:
            self.times.popleft()

        if len(self.times) >= self.threshold:
            self.hit.set()

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
        start = time.perf_counter()
        await self.hit.wait()

        return Result(
            detected=True,
            duration=time.perf_counter() - start,
            message=f"{len(self.times)} writes within {self.window}s",
        )


class HoneyPotDetector(Detector):
    """
    Plants a decoy PDF in safe_path and detects the first operation on it.

    Only modifying operations count by default so benign readers are not flagged. With
    include_reads any read counts too.
    """

    MUTATING_OPS: ClassVar[frozenset[Op]] = frozenset({Op.WRITE, Op.TRUNCATE, Op.UNLINK, Op.RENAME})

    NAME: ClassVar[str] = "winnie_the_pooh.pdf"

    ops: frozenset[Op]

    "Paths being watched, one for now"
    honeypots: set[str]
    hit: asyncio.Future[TraceEvent]

    def __init__(self, include_reads: bool = False) -> None:
        self.ops = (self.MUTATING_OPS | {Op.READ}) if include_reads else self.MUTATING_OPS

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.get_running_loop().create_future()
        self.honeypots = set()

        # Plain file I/O, not syscall, so planting is not traced
        fp = safe_path / self.NAME
        fp.write_bytes(minimal_pdf("Winnie the Pooh"))
        self.honeypots.add(str(fp))

        watched = ", ".join(sorted(self.ops))
        log(f"planted honeypot {fp}, watching {watched}")

    def on_event(self, event: TraceEvent) -> None:
        if event.op in self.ops and event.path in self.honeypots and not self.hit.done():
            self.hit.set_result(event)

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
        start = time.perf_counter()
        event = await self.hit

        return Result(
            detected=True,
            duration=time.perf_counter() - start,
            message=f"{event.op} on honeypot {event.path}",
        )


class FineTunedHoneyPotDetector(HoneyPotDetector):
    """
    Honeypot PDF with a big dead zone that viewers never read.

    Any modification counts, but a read only counts if it touches the dead zone. So a viewer
    is not flagged but something reading the whole file, like ransomware, is.
    """

    dead_zone: range
    log: Log

    def __init__(self) -> None:
        super().__init__(include_reads=False)

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.get_running_loop().create_future()
        self.log = log

        pdf, self.dead_zone = dead_zone_pdf("Winnie the Pooh")
        fp = safe_path / self.NAME
        fp.write_bytes(pdf)
        self.honeypots = {str(fp)}

        zone = self.dead_zone
        log(f"planted honeypot {fp}, {len(pdf)} bytes with dead zone [{zone.start}, {zone.stop})")

    def on_event(self, event: TraceEvent) -> None:
        if event.path not in self.honeypots or self.hit.done():
            return

        if event.op in self.ops:
            self.hit.set_result(event)
        elif event.op == Op.READ and self.__in_dead_zone(event):
            self.log(f"read {event.nbytes} bytes at {event.offset} touched the dead zone")
            self.hit.set_result(event)

    # Private

    def __in_dead_zone(self, event: TraceEvent) -> bool:
        if event.offset is None or not event.nbytes:  # nothing read, e.g. at EOF
            return False

        zone = self.dead_zone
        return event.offset < zone.stop and event.offset + event.nbytes > zone.start
