import pytest
import secrets

import client


class TestClient:
    key = secrets.token_bytes(16)
    msg = b"does it work?"
    msg_empty = b""

    def test_challenge_encryption(self):
        encrypted = client.challenge_encrypt(self.key, self.msg)
        assert self.msg == client.challenge_decrypt(self.key, encrypted)

    def test_challenge_encryption_empty(self):
        encrypted = client.challenge_encrypt(self.key, self.msg_empty)
        assert self.msg_empty == client.challenge_decrypt(self.key, encrypted)

    def test_decrypt(self):
        encrypted = client.encrypt(self.key, self.msg)
        assert client.encrypt == client.decrypt(self.key, encrypted)
    