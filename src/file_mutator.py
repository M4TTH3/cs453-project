"""
file_mutator.py provides FileMutator implementations, all file work goes through SysCall
"""

import asyncio
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from simulation import FileMutator, Log
from syscall import SysCall

CHUNK = 64 * 1024


def files_in(safe_path: Path) -> list[Path]:
    return sorted(p for p in safe_path.rglob("*") if p.is_file())


def read_all(syscall: SysCall, fd: int) -> bytes:
    parts: list[bytes] = []
    while chunk := syscall.read(fd, CHUNK):
        parts.append(chunk)
    return b"".join(parts)


def write_all(syscall: SysCall, fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[syscall.write(fd, bytes(view)) :]


class ReverseMutator(FileMutator):
    "Rewrites every file in place with its bytes reversed"

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            fd = syscall.open(fp, os.O_RDWR)
            try:
                data = read_all(syscall, fd)
                syscall.seek(fd, 0)
                syscall.truncate(fd, 0)
                write_all(syscall, fd, data[::-1])
            finally:
                syscall.close(fd)

            log(f"reversed {fp}")
            await asyncio.sleep(0)  # yield so the detector can run


class ReadOnlyMutator(FileMutator):
    "Benign, only reads files"

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            fd = syscall.open(fp, os.O_RDONLY)
            try:
                read_all(syscall, fd)
            finally:
                syscall.close(fd)

            log(f"read {fp}")
            await asyncio.sleep(0)


class BasicSymmetricEncryptionOverwrite(FileMutator):
    "Encrypts all files with a symmetric algorithm"

    def __init__(self):
        self.key = AESGCM.generate_key(bit_length=256)

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            fd = syscall.open(fp, os.O_RDONLY)
            try:
                data = read_all(syscall, fd)
                syscall.seek(fd, 0)
                syscall.truncate(fd, 0)

                nonce = os.urandom(12)
                out = nonce + AESGCM(self.key).encrypt(nonce, data, None)
                syscall.write(fd, out)
            finally:
                syscall.close(fd)

            log(f"read and encrypted {fp}")
            await asyncio.sleep(0)


class NoMutation(FileMutator):
    "Does nothing, so the detector only sees the unmodified data"

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        log("no mutation")
