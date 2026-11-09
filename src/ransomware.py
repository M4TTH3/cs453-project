"""
ransomware.py provides ransomware stuff
"""
from cryptography.fernet import Fernet


class Encrypter:
    key: str

    def __init__(self, key: str) -> None:
        self.key = key

    @staticmethod
    def generate_key():
        return Fernet.generate_key()
