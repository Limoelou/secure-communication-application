import pytest
import secrets

import client


class TestClient:
    key = secrets.token_bytes(16)

    def test_challenge_encryption(self):
        msg = b"does it work?"
        encrypted = client.challenge_encrypt(self.key, msg)
        assert msg == client.challenge_decrypt(self.key, encrypted)

    def test_challenge_encryption_empty(self):
        msg = b""
        encrypted = client.challenge_encrypt(self.key, msg)
        assert msg == client.challenge_decrypt(self.key, encrypted)
