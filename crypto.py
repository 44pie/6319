"""
6319 Crypto Module
End-to-end encryption using NaCl SecretBox (XSalsa20-Poly1305)
"""

import hashlib
import os
import json
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.exceptions import CryptoError


def derive_key(secret: str) -> bytes:
    """Derive 32-byte key from secret - must match agent's Ch class"""
    return hashlib.sha256(secret.encode()).digest()


class SecureChannel:
    """Encrypted communication channel using NaCl SecretBox"""
    
    def __init__(self, secret: str):
        self.key = derive_key(secret)
        self.box = SecretBox(self.key)
    
    def encrypt(self, data: dict) -> bytes:
        """Encrypt JSON data to bytes"""
        plaintext = json.dumps(data).encode()
        nonce = nacl_random(SecretBox.NONCE_SIZE)
        ciphertext = self.box.encrypt(plaintext, nonce)
        return ciphertext
    
    def decrypt(self, data: bytes) -> dict:
        """Decrypt bytes to JSON data"""
        try:
            plaintext = self.box.decrypt(data)
            return json.loads(plaintext.decode())
        except (CryptoError, json.JSONDecodeError):
            return None
    
    def encrypt_frame(self, data: dict) -> bytes:
        """Encrypt with length prefix for socket transmission"""
        encrypted = self.encrypt(data)
        length = len(encrypted)
        return length.to_bytes(4, 'big') + encrypted
    
    def decrypt_frame(self, data: bytes) -> dict:
        """Decrypt length-prefixed frame"""
        if len(data) < 4:
            return None
        length = int.from_bytes(data[:4], 'big')
        if len(data) < 4 + length:
            return None
        return self.decrypt(data[4:4+length])


def generate_secret() -> str:
    """Generate random 32-char hex secret"""
    return os.urandom(16).hex()


def verify_secret(secret: str) -> bool:
    """Verify secret format"""
    if not secret or len(secret) < 8:
        return False
    return True
