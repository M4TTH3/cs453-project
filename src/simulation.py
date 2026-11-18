"""
simulation.py runs a FileMutator against a Detector on a copy of the data
"""

import asyncio
import random
import shutil
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel

from syscall import SysCall, TraceEvent


class Result(BaseModel):
    detected: bool

    "Seconds"
    duration: float

    message: str


class RunLog:
    "Log lines of one run, in order"

    lines: list[str]

    def __init__(self) -> None:
        self.lines = []

    def bind(self, name: str) -> Log:
        "Log that prefixes its lines with `name: `"
        return Log(self, name)

    def save(self, fp: Path) -> None:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text("".join(line + "\n" for line in self.lines))


class Log:
    'log("msg") appends `name: msg` to the run log'

    __run: RunLog
    __name: str

    def __init__(self, run: RunLog, name: str) -> None:
        self.__run = run
        self.__name = name

    def __call__(self, msg: str) -> None:
        self.__run.lines.append(f"{self.__name}: {msg}")


class Detector(ABC):
    "Decides if file activity is an attack. Returns once it has a verdict"

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        "Runs once before the mutator and detector start. Does nothing by default"

    def on_event(self, event: TraceEvent) -> None:
        "Called for every syscall as it happens. Does nothing by default"

    @abstractmethod
    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
        """
        Can wait on state set by on_event, poll safe_path, etc.

        With finish_mutator_first the mutator is already done, so on_event has seen the
        full trace and safe_path is the final state.
        """


class FileMutator(ABC):
    "Does file work in safe_path. Should go through syscall so it is traced"

    @abstractmethod
    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None: ...


class Simulator:
    data_path: Path

    "Seconds the detector gets once the mutator is done"
    grace: float

    def __init__(self, data_path: Path, grace: float = 1.0) -> None:
        self.data_path = data_path
        self.grace = grace

    async def run(
        self,
        detector: Detector,
        mutator: FileMutator,
        finish_mutator_first: bool = False,
        log_path: Path | None = None,
    ) -> Result:
        """
        Copies data_path to a tmpdir (safe_path) and runs both against it with a fresh SysCall
        using a random PID. The copy is deleted after.

        They run concurrently by default and the first detector Result wins. With
        finish_mutator_first the mutator completes before the detector starts, for static
        analysis. Either way the detector gets `grace` seconds once the mutator is done.

        The run log is saved to log_path if given.
        """
        runlog = RunLog()
        sim_log = runlog.bind("simulator")

        try:
            with tempfile.TemporaryDirectory(prefix="sim-") as tmp:
                safe_path = Path(tmp) / self.data_path.name
                shutil.copytree(self.data_path, safe_path)

                syscall = SysCall(pid=random.randint(2, 2**22))
                sim_log(f"safe_path={safe_path} pid={syscall.pid} grace={self.grace}")
                sim_log(f"finish_mutator_first={finish_mutator_first}")

                det_log = runlog.bind("detector")
                detector.setup(syscall, safe_path, det_log)
                syscall.subscribe(detector.on_event)

                det_coro = detector.start(syscall, safe_path, det_log)
                mut_coro = mutator.start(syscall, safe_path, runlog.bind("mutator"))
                start = time.perf_counter()

                if finish_mutator_first:
                    result = await self.__sequential(det_coro, mut_coro, start)
                else:
                    result = await self.__concurrent(det_coro, mut_coro, start)

                sim_log(f"result: {result}")
                sim_log(f"{len(syscall.events)} syscalls traced")
                return result
        finally:
            if log_path is not None:
                runlog.save(log_path)

    # Private

    async def __concurrent(self, det_coro, mut_coro, start: float) -> Result:
        det = asyncio.create_task(det_coro)
        mut = asyncio.create_task(mut_coro)

        try:
            done, _ = await asyncio.wait({det, mut}, return_when=asyncio.FIRST_COMPLETED)
            if det in done:
                return det.result()

            mut.result()  # raise mutator errors
            return await self.__verdict(det, start)
        finally:
            for t in (det, mut):
                t.cancel()
            await asyncio.gather(det, mut, return_exceptions=True)

    async def __sequential(self, det_coro, mut_coro, start: float) -> Result:
        try:
            await mut_coro
        except BaseException:
            det_coro.close()  # was never started
            raise

        det = asyncio.create_task(det_coro)
        try:
            return await self.__verdict(det, start)
        finally:
            det.cancel()
            await asyncio.gather(det, return_exceptions=True)

    async def __verdict(self, det: asyncio.Task[Result], start: float) -> Result:
        "Detector Result, or not detected after `grace` seconds"
        try:
            return await asyncio.wait_for(det, self.grace)
        except TimeoutError:
            return Result(
                detected=False,
                duration=time.perf_counter() - start,
                message=f"no verdict within {self.grace}s after the mutator finished",
            )
