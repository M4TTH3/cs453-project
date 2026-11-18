"""
file_mutator.py provides FileMutator implementations, all file work goes through SysCall
"""

import asyncio
import os
import random
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
            fd = syscall.open(fp, os.O_RDWR)
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


class SplitProcessEncryption(FileMutator):
    "Encrypts all files, but one simulated process only reads and another only writes"

    def __init__(self):
        self.key = AESGCM.generate_key(bit_length=256)

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        reader_pid, writer_pid = random.sample(range(2, 2**22), 2)
        reader = syscall.as_pid(reader_pid)
        writer = syscall.as_pid(writer_pid)

        for fp in files_in(safe_path):
            fd = reader.open(fp, os.O_RDONLY)
            try:
                data = read_all(reader, fd)
            finally:
                reader.close(fd)

            nonce = os.urandom(12)
            out = nonce + AESGCM(self.key).encrypt(nonce, data, None)

            fd = writer.open(fp, os.O_WRONLY)
            try:
                writer.truncate(fd, 0)
                write_all(writer, fd, out)
            finally:
                writer.close(fd)

            log(f"pid {reader_pid} read, pid {writer_pid} encrypted {fp}")
            await asyncio.sleep(0)


class PartialEncryption(FileMutator):
    "Encrypts only the first `ratio` of each file in place. The rest is never read or written"

    def __init__(self, ratio: float = 0.5):
        self.ratio = ratio
        self.key = os.urandom(32)

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            n = int(fp.stat().st_size * self.ratio)

            fd = syscall.open(fp, os.O_RDWR)
            try:
                head = b""
                while len(head) < n and (chunk := syscall.read(fd, min(CHUNK, n - len(head)))):
                    head += chunk

                # CTR keeps the length, so the ciphertext fits back in place
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(os.urandom(16)))
                out = cipher.encryptor().update(head)

                syscall.seek(fd, 0)
                write_all(syscall, fd, out)
            finally:
                syscall.close(fd)

            log(f"encrypted first {n} bytes of {fp}")
            await asyncio.sleep(0)


class PaddedEncryption(FileMutator):
    "Encrypts all files, with `pad` zero bytes after every ciphertext byte to lower entropy"

    def __init__(self, pad: int = 2):
        self.pad = pad
        self.key = AESGCM.generate_key(bit_length=256)

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        for fp in files_in(safe_path):
            fd = syscall.open(fp, os.O_RDWR)
            try:
                data = read_all(syscall, fd)
                nonce = os.urandom(12)
                ct = nonce + AESGCM(self.key).encrypt(nonce, data, None)

                padded = bytearray(len(ct) * (self.pad + 1))
                padded[:: self.pad + 1] = ct

                syscall.seek(fd, 0)
                syscall.truncate(fd, 0)
                write_all(syscall, fd, bytes(padded))
            finally:
                syscall.close(fd)

            log(f"encrypted and padded {fp}")
            await asyncio.sleep(0)


class NoMutation(FileMutator):
    "Does nothing, so the detector only sees the unmodified data"

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        log("no mutation")
