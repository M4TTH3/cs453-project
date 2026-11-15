"""
detectors.py provides Detector implementations
"""

import asyncio
import time
from collections import deque
from pathlib import Path

from simulation import Detector, Log, Result
from syscall import Op, SysCall, TraceEvent


class WriteBurstDetector(Detector):
    "Detects when `threshold` writes happen within `window` seconds"

    threshold: int
    window: float

    def __init__(self, threshold: int = 10, window: float = 1.0) -> None:
        self.threshold = threshold
        self.window = window

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
        start = time.perf_counter()
        hit = asyncio.Event()
        times: deque[float] = deque()

        def on_event(e: TraceEvent) -> None:
            if e.op != Op.WRITE:
                return

            times.append(e.ts)
            while e.ts - times[0] > self.window:
                times.popleft()

            if len(times) >= self.threshold:
                hit.set()

        log(f"threshold={self.threshold} writes, window={self.window}s")

        # replay past events, the mutator may already be done
        for e in list(syscall.events):
            on_event(e)
        syscall.subscribe(on_event)
        await hit.wait()

        return Result(
            detected=True,
            duration=time.perf_counter() - start,
            message=f"{len(times)} writes within {self.window}s",
        )
