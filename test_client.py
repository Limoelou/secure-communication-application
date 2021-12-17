from Crypto.Cipher.AES import block_size
import pytest
import secrets

import client


class TestClient:
    key = secrets.token_bytes(32)
    msg = b"does it work?"
    msg_empty = b""
    hash = b'31f7a65e315586ac198bd798b6629ce4903d0899476d5741a9f32e2e521b6a66'

    def test_challenge_encryption(self):
        encrypted = client.challenge_encrypt(self.key, self.msg)
        assert self.msg == client.challenge_decrypt(self.key, encrypted)

    def test_challenge_encryption_empty(self):
        encrypted = client.challenge_encrypt(self.key, self.msg_empty)
        assert self.msg_empty == client.challenge_decrypt(self.key, encrypted)

    def test_challenge_encryption_hash(self):
        encrypted = client.challenge_encrypt(self.key, self.hash)
        assert self.hash == client.challenge_decrypt(self.key, encrypted)

    def test_decrypt(self):
        encrypted = client.encrypt(self.key, self.msg)
        assert self.msg == client.decrypt(encrypted, self.key)
