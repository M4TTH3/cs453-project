"""
file_mutator.py provides FileMutator implementations, all file work goes through SysCall
"""

import asyncio
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pypdf import PdfReader

from simulation import FileMutator, Log
from syscall import SysCall
from traced_file import TracedFile

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


class PdfReaderMutator(FileMutator):
    """
    Benign, reads PDFs like a viewer. Reads the head and tail, then each object reachable
    from the catalog, in small reads that never cover the whole file.
    """

    HEAD = 1024
    TAIL = 1024
    PIECE = 512

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            if fp.suffix.lower() != ".pdf":
                continue

            fd = syscall.open(fp, os.O_RDONLY)
            try:
                objects = self.__read_pdf(syscall, fd)
            finally:
                syscall.close(fd)

            log(f"loaded {objects} objects of {fp}" if objects is not None else f"skipped {fp}")
            await asyncio.sleep(0)

    # Private

    def __read_pdf(self, syscall: SysCall, fd: int) -> int | None:
        "Number of objects loaded, None if there is no xref to follow"
        syscall.seek(fd, 0)
        if not syscall.read(fd, self.HEAD).startswith(b"%PDF-"):
            return None

        size = syscall.seek(fd, 0, os.SEEK_END)
        syscall.seek(fd, max(0, size - self.TAIL))
        startxref = re.search(rb"startxref\s+(\d+)", syscall.read(fd, self.TAIL))
        if startxref is None:
            return None

        syscall.seek(fd, int(startxref.group(1)))
        table = b""
        while b"startxref" not in table:
            piece = syscall.read(fd, self.PIECE)
            if not piece:
                return None
            table += piece

        # Object number to offset
        entries = re.findall(rb"(\d{10}) \d{5} ([nf]) ", table)
        offsets = {num: int(off) for num, (off, kind) in enumerate(entries) if kind == b"n"}
        root = re.search(rb"/Root\s+(\d+) 0 R", table)
        if root is None:
            return None

        # Only load objects reachable from the catalog
        todo, loaded = [int(root.group(1))], set[int]()
        while todo:
            num = todo.pop()
            if num in loaded or num not in offsets:
                continue

            loaded.add(num)
            body = self.__read_object(syscall, fd, offsets[num])
            todo += [int(ref) for ref in re.findall(rb"(\d+) 0 R", body)]

        return len(loaded)

    def __read_object(self, syscall: SysCall, fd: int, offset: int) -> bytes:
        syscall.seek(fd, offset)
        obj = b""
        while b"endobj" not in obj:
            piece = syscall.read(fd, self.PIECE)
            if not piece:
                break
            obj += piece

        return obj


class PypdfReaderMutator(FileMutator):
    "Benign, reads PDFs with pypdf. Its file reads go through SysCall via TracedFile"

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            if fp.suffix.lower() != ".pdf":
                continue

            with TracedFile(syscall, fp) as f:
                reader = PdfReader(f)
                pages = [page.extract_text() for page in reader.pages]

            log(f"read {len(pages)} pages of {fp}")
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
