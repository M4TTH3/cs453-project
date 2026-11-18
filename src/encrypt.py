"""
ransomware.py provides ransomware stuff
"""

import io
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import BaseModel

from exception import FileNotInDataError

"""
Encryption utility for test data to test our entropy detector
"""


class Encrypter:
    class Options(BaseModel):
        "Encrypt every other {every_kb} block in the file"

        every_kb: int | None

        "Allowed paths"
        allowed: set[Path]

    key: bytes
    fernet: Fernet
    options: Options

    def __init__(self, key: bytes, options: Options) -> None:
        self.fernet = Fernet(key)
        self.key = key
        self.options = options

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    @staticmethod
    def save_key(fp: Path, key: bytes):
        fp.write_bytes(key)

    @staticmethod
    def load_key(fp: Path) -> bytes:
        return fp.read_bytes()

    def encrypt(self, fp: Path):
        """
        Symmetric AES encryption
        """
        if fp not in self.options.allowed:
            raise FileNotInDataError()

        if fp.is_dir():
            for p in fp.iterdir():
                self.encrypt(p)
            return

        if self.options.every_kb:
            data = io.BytesIO()
            with open(fp, "rb") as f:
                counter = 0
                while True:
                    if tmp := f.read(self.options.every_kb):
                        enc_chunk = self.fernet.encrypt(tmp)
                        data.write(enc_chunk if counter % 2 == 0 else tmp)
                    else:
                        break

                    counter += 1

            encrypted = data.read()

        else:
            data = fp.read_bytes()
            encrypted = self.fernet.encrypt(data)

        fp.write_bytes(encrypted)

    def decrypt(self, fp: Path):
        """
        Symmetric AES decryption
        """
        if fp not in self.options.allowed:
            raise FileNotInDataError()

        if fp.is_dir():
            for p in fp.iterdir():
                self.encrypt(p)

        if self.options.every_kb:
            data = io.BytesIO()
            with open(fp, "rb") as f:
                counter = 0
                while True:
                    if tmp := f.read(self.options.every_kb):
                        enc_chunk = self.fernet.decrypt(tmp)
                        data.write(enc_chunk if counter % 2 == 0 else tmp)
                    else:
                        break

                    counter += 1

            decrypted = data.read()

        else:
            data = fp.read_bytes()
            decrypted = self.fernet.decrypt(data)

        fp.write_bytes(decrypted)
