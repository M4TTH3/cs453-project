"""
syscall.py wraps the low-level file operations and records a TraceEvent for each call
"""

import os
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field


class Op(StrEnum):
    "Operations SysCall traces"

    OPEN = "open"
    READ = "read"
    WRITE = "write"
    SEEK = "seek"
    TRUNCATE = "truncate"
    CLOSE = "close"
    UNLINK = "unlink"
    RENAME = "rename"


type Extra = dict[str, str | int | None]


class TraceEvent(BaseModel):
    "One recorded operation"

    seq: int
    ts: float
    pid: int
    op: Op
    path: str | None = None
    fd: int | None = None
    nbytes: int | None = None
    offset: int | None = None
    ok: bool = True
    error: str | None = None
    extra: Extra = {}

    "Bytes transferred by a read or write, kept in memory only"
    data: bytes | None = Field(default=None, exclude=True, repr=False)


class SysCall:
    "Traced file operations. Uses raw fds so each call maps to one syscall"

    events: list[TraceEvent]
    listeners: list[Callable[[TraceEvent], None]]
    pid: int | None
    log: bool

    "Keep the bytes transferred by each read or write on its event"
    capture: bool

    __paths: dict[int, Path]

    def __init__(
        self,
        pid: int | None = None,
        log: bool = False,
        capture: bool = True,
    ) -> None:
        "pid is stamped on every event, defaults to os.getpid()"
        self.pid = pid
        self.capture = capture
        self.events = []
        self.listeners = []
        self.log = log
        self.__paths = {}

    def subscribe(self, fn: Callable[[TraceEvent], None]) -> None:
        "Call fn for every new event"
        self.listeners.append(fn)

    def clear(self) -> None:
        self.events.clear()

    def dump(self, fp: Path) -> None:
        "Write the trace as JSON lines"
        fp.parent.mkdir(parents=True, exist_ok=True)
        with open(fp, "w") as f:
            f.writelines(e.model_dump_json(exclude_none=True) + "\n" for e in self.events)

    def ops(self, op: Op | None = None, path: Path | None = None) -> list[TraceEvent]:
        "Events matching op and/or path"
        p = str(path) if path is not None else None
        return [e for e in self.events if (op is None or e.op == op) and (p is None or e.path == p)]

    def open(self, path: Path, flags: int = os.O_RDONLY, mode: int = 0o666) -> int:
        "Returns the raw fd"
        try:
            fd = os.open(path, flags, mode)
        except OSError as exc:
            self.__fail(Op.OPEN, exc, path=str(path), extra={"flags": flags})
            raise
        self.__paths[fd] = Path(path)
        self.__record(Op.OPEN, path=str(path), fd=fd, extra={"flags": flags})
        return fd

    def read(self, fd: int, n: int) -> bytes:
        "Read up to n bytes at the current offset"
        try:
            offset = os.lseek(fd, 0, os.SEEK_CUR)
            data = os.read(fd, n)
        except OSError as exc:
            self.__fail(Op.READ, exc, fd=fd, path=self.__path(fd))
            raise
        self.__record(
            Op.READ,
            fd=fd,
            path=self.__path(fd),
            nbytes=len(data),
            offset=offset,
            data=data if self.capture else None,
        )
        return data

    def write(self, fd: int, data: bytes) -> int:
        "Write data at the current offset"
        try:
            offset = os.lseek(fd, 0, os.SEEK_CUR)
            written = os.write(fd, data)
        except OSError as exc:
            self.__fail(Op.WRITE, exc, fd=fd, path=self.__path(fd))
            raise
        self.__record(
            Op.WRITE,
            fd=fd,
            path=self.__path(fd),
            nbytes=written,
            offset=offset,
            data=self.__captured(data, written),
        )
        return written

    def seek(self, fd: int, offset: int, whence: int = os.SEEK_SET) -> int:
        try:
            pos = os.lseek(fd, offset, whence)
        except OSError as exc:
            self.__fail(Op.SEEK, exc, fd=fd, path=self.__path(fd))
            raise
        self.__record(Op.SEEK, fd=fd, path=self.__path(fd), offset=pos, extra={"whence": whence})
        return pos

    def truncate(self, fd: int, length: int = 0) -> None:
        try:
            os.ftruncate(fd, length)
        except OSError as exc:
            self.__fail(Op.TRUNCATE, exc, fd=fd, path=self.__path(fd))
            raise
        self.__record(Op.TRUNCATE, fd=fd, path=self.__path(fd), nbytes=length)

    def close(self, fd: int) -> None:
        path = self.__path(fd)
        try:
            os.close(fd)
        except OSError as exc:
            self.__fail(Op.CLOSE, exc, fd=fd, path=path)
            raise
        self.__paths.pop(fd, None)
        self.__record(Op.CLOSE, fd=fd, path=path)

    def unlink(self, path: Path) -> None:
        try:
            os.unlink(path)
        except OSError as exc:
            self.__fail(Op.UNLINK, exc, path=str(path))
            raise
        self.__record(Op.UNLINK, path=str(path))

    def rename(self, src: Path, dst: Path) -> None:
        try:
            os.rename(src, dst)
        except OSError as exc:
            self.__fail(Op.RENAME, exc, path=str(src), extra={"dst": str(dst)})
            raise
        self.__record(Op.RENAME, path=str(src), extra={"dst": str(dst)})

    # Private

    def __record(
        self,
        op: Op,
        *,
        path: str | None = None,
        fd: int | None = None,
        nbytes: int | None = None,
        offset: int | None = None,
        ok: bool = True,
        error: str | None = None,
        extra: Extra | None = None,
        data: bytes | None = None,
    ) -> TraceEvent:
        event = TraceEvent(
            seq=len(self.events),
            ts=time.time(),
            pid=self.pid if self.pid is not None else os.getpid(),
            op=op,
            path=path,
            fd=fd,
            nbytes=nbytes,
            offset=offset,
            ok=ok,
            error=error,
            extra=extra or {},
            data=data,
        )
        self.events.append(event)
        if self.log:
            logger.debug(event.model_dump_json(exclude_none=True))
        for fn in self.listeners:
            fn(event)
        return event

    def __fail(
        self,
        op: Op,
        exc: OSError,
        *,
        path: str | None = None,
        fd: int | None = None,
        extra: Extra | None = None,
    ) -> None:
        error = f"{type(exc).__name__}: {exc}"
        self.__record(op, path=path, fd=fd, ok=False, error=error, extra=extra)

    def __captured(self, data: bytes, written: int) -> bytes | None:
        "The part of data to keep on the event"
        if not self.capture:
            return None

        return data if written == len(data) else data[:written]

    def __path(self, fd: int) -> str | None:
        p = self.__paths.get(fd)
        return str(p) if p is not None else None
