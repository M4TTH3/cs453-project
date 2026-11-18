"""
detectors.py provides Detector implementations
"""

import asyncio
import time
from collections import deque
from pathlib import Path
from typing import ClassVar

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


def minimal_pdf(text: str) -> bytes:
    "A valid one page PDF showing `text`. Built by hand, no PDF library needed"
    stream = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R",
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    out = b"%PDF-1.4\n"
    offsets: list[int] = []
    for num, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (num, body)

    # The xref table lists the byte offset of every object
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return out


class HoneyPotDetector(Detector):
    """
    Plants a decoy PDF in safe_path that nothing legitimate touches and detects the first
    operation on it.

    By default only operations that modify a honeypot count, so a benign reader (backup,
    scanner) is not flagged. With include_reads a plain read counts too, which detects
    earlier but flags those readers.
    """

    MUTATING_OPS: ClassVar[frozenset[Op]] = frozenset({Op.WRITE, Op.TRUNCATE, Op.UNLINK, Op.RENAME})

    ops: frozenset[Op]

    "Paths being watched, one for now"
    honeypots: set[str]
    hit: asyncio.Future[TraceEvent]

    def __init__(self, include_reads: bool = False) -> None:
        self.ops = (self.MUTATING_OPS | {Op.READ}) if include_reads else self.MUTATING_OPS

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.get_running_loop().create_future()
        self.honeypots = set()

        # Directly under safe_path. Plain file I/O, not syscall, so planting is not traced.
        fp = safe_path / "winnie_the_pooh.pdf"
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
