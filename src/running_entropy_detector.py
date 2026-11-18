"""
Implements the per-process entropy indicator from Scaife, Carter, Traynor & Butler (2016),
"CryptoLock (and Drop It): Stopping Ransomware Attacks on User Data",
https://www.cise.ufl.edu/~butler/pubs/icdcs16.pdf

Section III C describes how to measure Shannon entropy from the distribution of byte
values. Section IV C1 applies that measurement to individual reads and writes, then
tracks separate cumulative weighted averages for each process. The weighting gives
smaller, lower-entropy operations less influence on those averages.

The detector flags a process when its average write entropy exceeds its average read
entropy by at least the threshold. This asymmetry can indicate file encryption.
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path

from entropy_analysis import calculate_shannon
from simulation import Detector, Log, Result
from syscall import Op, SysCall, TraceEvent


@dataclass
class EntropyTotals:
    weighted_sum: float = 0.0
    total_weight: float = 0.0


@dataclass
class ProcessEntropy:
    reads: EntropyTotals = field(default_factory=EntropyTotals)
    writes: EntropyTotals = field(default_factory=EntropyTotals)


class RunningEntropyDetector(Detector):
    """Detect a cumulative increase in entropy from reads to writes by the same PID."""

    threshold = 0.1

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.processes: dict[int, ProcessEntropy] = {}
        self.hit: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        log(f"write-minus-read entropy threshold={self.threshold} bits per byte")

    def on_event(self, event: TraceEvent) -> None:
        if self.hit.done() or not event.ok or not event.data or event.op not in (Op.READ, Op.WRITE):
            return

        entropy = calculate_shannon(event.data)
        weight = (round(entropy) / 8) * len(event.data)
        if weight == 0:
            return

        process = self.processes.get(event.pid)
        if process is None:
            process = self.processes[event.pid] = ProcessEntropy()

        totals = process.reads if event.op == Op.READ else process.writes
        totals.weighted_sum += weight * entropy
        totals.total_weight += weight

        if not process.reads.total_weight or not process.writes.total_weight:
            return

        read_average = process.reads.weighted_sum / process.reads.total_weight
        write_average = process.writes.weighted_sum / process.writes.total_weight
        delta = write_average - read_average
        if delta >= self.threshold:
            self.hit.set_result(
                f"pid={event.pid} {event.op} seq={event.seq}: read={read_average:.4f}, "
                f"write={write_average:.4f}, delta={delta:.4f} bits per byte"
            )

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
        start = time.perf_counter()
        message = await self.hit
        return Result(detected=True, duration=time.perf_counter() - start, message=message)
