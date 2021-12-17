from Crypto.Cipher.AES import block_size
import pytest
import secrets

import client


class TestClient:
    key = secrets.token_bytes(32)
    msg = b"does it work?"
    msg_empty = b""

    def test_challenge_encryption(self):
        encrypted, key = client.challenge_encrypt(self.key, self.msg)
        assert self.msg == client.challenge_decrypt(self.key, encrypted)

    def test_challenge_encryption_empty(self):
        encrypted, _ = client.challenge_encrypt(self.key, self.msg_empty)
        assert self.msg_empty == client.challenge_decrypt(self.key, encrypted)

    def test_decrypt(self):
        encrypted = client.encrypt(self.key, self.msg)
        assert self.msg == client.decrypt(encrypted, self.key)
    