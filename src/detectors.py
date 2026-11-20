"""
detectors.py provides Detector implementations
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections import Counter, deque
from collections.abc import Callable
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
    Plants a decoy PDF in safe_path and detects the first write, truncate, unlink or rename
    of it. Reads never count, so benign readers are not flagged.
    """

    MUTATING_OPS: ClassVar[frozenset[Op]] = frozenset({Op.WRITE, Op.TRUNCATE, Op.UNLINK, Op.RENAME})

    NAME: ClassVar[str] = "winnie_the_pooh.pdf"

    "Decoy filename, which decides where in a sorted traversal the attacker reaches it"
    name: str

    "Paths being watched, one for now"
    honeypots: set[str]
    hit: asyncio.Future[TraceEvent]

    def __init__(self, name: str = NAME) -> None:
        self.name = name

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.get_running_loop().create_future()
        self.honeypots = set()

        # Plain file I/O, not syscall, so planting is not traced
        fp = safe_path / self.name
        fp.write_bytes(minimal_pdf("Winnie the Pooh"))
        self.honeypots.add(str(fp))

        watched = ", ".join(sorted(self.MUTATING_OPS))
        log(f"planted honeypot {fp}, watching {watched}")

    def on_event(self, event: TraceEvent) -> None:
        if event.op in self.MUTATING_OPS and event.path in self.honeypots and not self.hit.done():
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

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.get_running_loop().create_future()
        self.log = log

        pdf, self.dead_zone = dead_zone_pdf("Winnie the Pooh")
        fp = safe_path / self.name
        fp.write_bytes(pdf)
        self.honeypots = {str(fp)}

        zone = self.dead_zone
        log(f"planted honeypot {fp}, {len(pdf)} bytes with dead zone [{zone.start}, {zone.stop})")

    def on_event(self, event: TraceEvent) -> None:
        if event.path not in self.honeypots or self.hit.done():
            return

        if event.op in self.MUTATING_OPS:
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


"Sorts before real files, so a traversal in sorted order reaches the decoy first"
EARLY_NAME = "0000-invoice.pdf"


class EarlyHoneyPotDetector(HoneyPotDetector):
    "HoneyPotDetector with the decoy at the front of the traversal instead of the end"

    def __init__(self, name: str = EARLY_NAME) -> None:
        super().__init__(name)


class EarlyFineTunedHoneyPotDetector(FineTunedHoneyPotDetector):
    "FineTunedHoneyPotDetector with the decoy at the front of the traversal"

    def __init__(self, name: str = EARLY_NAME) -> None:
        super().__init__(name)


type Combine = Callable[[list[tuple[float, float]]], float]

# Ops that change a file. Opens are counted separately and do not affect the score.
MODIFYING_OPS = {Op.WRITE, Op.TRUNCATE, Op.UNLINK, Op.RENAME}

# extension -> bytes expected at offset 0. csv and txt have no signature.
SIGNATURES: dict[str, bytes] = {
    ".7z": b"\x37\x7a\xbc\xaf\x27\x1c",
    ".doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".docx": b"PK\x03\x04",
    ".pdf": b"%PDF",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".zip": b"PK\x03\x04",
}
TEXT_EXTS = {".csv", ".txt"}


def weighted_sum(parts: list[tuple[float, float]]) -> float:
    "Default combine: sum of score * weight"
    return sum(score * weight for score, weight in parts)


def _binary(data: bytes) -> bool:
    "True when data is not valid text"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


class ScoredDetector(Detector, ABC):
    "Scores trace events from 0 to 1. start() returns once the score reaches 1"

    hit: asyncio.Event

    @abstractmethod
    def reset(self) -> None: ...

    @abstractmethod
    def observe(self, event: TraceEvent) -> None: ...

    @abstractmethod
    def score(self) -> float: ...

    @abstractmethod
    def reason(self) -> str: ...

    @abstractmethod
    def config(self) -> str: ...

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.Event()
        self.reset()
        log(self.config())

    def on_event(self, event: TraceEvent) -> None:
        if not event.ok or self.hit.is_set():
            return

        self.observe(event)
        if self.score() >= 1.0:
            self.hit.set()

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
        start = time.perf_counter()
        await self.hit.wait()

        return Result(
            detected=True,
            duration=time.perf_counter() - start,
            message=self.reason(),
        )


class FileVelocityDetector(ScoredDetector):
    "Distinct files modified within `window` seconds. Opens are reported, not scored"

    files_threshold: int
    window: float

    def __init__(self, files_threshold: int = 20, window: float = 1.0) -> None:
        self.files_threshold = files_threshold
        self.window = window
        self.reset()

    def reset(self) -> None:
        self._modified: deque[tuple[float, str]] = deque()
        self._modified_counts: Counter[str] = Counter()
        self._opened: deque[tuple[float, str]] = deque()
        self._opened_counts: Counter[str] = Counter()

    def observe(self, event: TraceEvent) -> None:
        if event.path is None:
            return
        if event.op == Op.OPEN:
            self._add(self._opened, self._opened_counts, event.ts, event.path)
        elif event.op in MODIFYING_OPS:
            self._add(self._modified, self._modified_counts, event.ts, event.path)

    def score(self) -> float:
        return min(len(self._modified_counts) / self.files_threshold, 1.0)

    def reason(self) -> str:
        return (
            f"{len(self._modified_counts)} modified, "
            f"{len(self._opened_counts)} opened, in {self.window}s"
        )

    def config(self) -> str:
        return f"files_threshold={self.files_threshold}, window={self.window}s"

    def _add(
        self,
        events: deque[tuple[float, str]],
        counts: Counter[str],
        ts: float,
        path: str,
    ) -> None:
        events.append((ts, path))
        counts[path] += 1
        while events and ts - events[0][0] > self.window:
            _, old = events.popleft()
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]


class FileTypeChangeDetector(ScoredDetector):
    "Known header overwritten, or text rewritten as non-text"

    files_threshold: int

    def __init__(self, files_threshold: int = 5) -> None:
        self.files_threshold = files_threshold
        self.reset()

    def reset(self) -> None:
        self._checked: set[str] = set()
        self._suspicious: set[str] = set()
        self._counts: Counter[str] = Counter()

    def observe(self, event: TraceEvent) -> None:
        if event.op != Op.WRITE or event.path is None or event.offset != 0:
            return
        if event.path in self._checked:
            return
        self._checked.add(event.path)

        ext = Path(event.path).suffix.lower()
        data = event.data or b""
        magic = SIGNATURES.get(ext)
        if magic is not None and not data.startswith(magic):
            self._hit(event.path, "header")
        elif ext in TEXT_EXTS and _binary(data):
            self._hit(event.path, "text")

    def score(self) -> float:
        return min(len(self._suspicious) / self.files_threshold, 1.0)

    def reason(self) -> str:
        counts = ", ".join(f"{name}={n}" for name, n in sorted(self._counts.items())) or "none"
        return f"{len(self._suspicious)} files ({counts})"

    def config(self) -> str:
        return f"files_threshold={self.files_threshold}"

    def _hit(self, path: str, kind: str) -> None:
        self._suspicious.add(path)
        self._counts[kind] += 1


class CompositeDetector(ScoredDetector):
    "Combines scored detectors. Each weight is applied to that detector's 0..1 score"

    def __init__(
        self,
        members: list[tuple[ScoredDetector, float]] | None = None,
        combine: Combine = weighted_sum,
        threshold: float = 1.0,
    ) -> None:
        if members is None:
            members = [(FileVelocityDetector(), 1.0), (FileTypeChangeDetector(), 1.0)]
        self.members = members
        self.combine = combine
        self.threshold = threshold

    def reset(self) -> None:
        for det, _ in self.members:
            det.reset()

    def observe(self, event: TraceEvent) -> None:
        for det, _ in self.members:
            det.observe(event)

    def score(self) -> float:
        total = self.combine([(det.score(), weight) for det, weight in self.members])
        return min(total / self.threshold, 1.0)

    def reason(self) -> str:
        return "; ".join(
            f"{type(det).__name__} {det.score():.2f} ({det.reason()})" for det, _ in self.members
        )

    def config(self) -> str:
        members = ", ".join(f"{type(det).__name__}*{weight:g}" for det, weight in self.members)
        return f"{self.combine.__name__}, threshold={self.threshold:g} [{members}]"
