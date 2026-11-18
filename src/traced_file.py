"""
traced_file.py gives libraries a file object whose reads go through SysCall
"""

import io
import os
from collections.abc import Buffer
from pathlib import Path

from syscall import SysCall


class TracedFile(io.RawIOBase):
    "Read only file object over SysCall. Not buffered, so each library read is one traced read"

    syscall: SysCall
    fd: int

    def __init__(self, syscall: SysCall, path: Path) -> None:
        self.syscall = syscall
        self.fd = syscall.open(path, os.O_RDONLY)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, buffer: Buffer) -> int:
        view = memoryview(buffer)
        data = self.syscall.read(self.fd, len(view))
        view[: len(data)] = data
        return len(data)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.syscall.seek(self.fd, offset, whence)

    def tell(self) -> int:
        return self.syscall.seek(self.fd, 0, os.SEEK_CUR)

    def close(self) -> None:
        if not self.closed:
            self.syscall.close(self.fd)
        super().close()
