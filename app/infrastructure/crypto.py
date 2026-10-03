"""SHA-256 and a persistent local Ed25519 key for training packages."""

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import STORAGE_ROOT


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class TrainingSigner:
    def __init__(self, key_path: Path | None = None) -> None:
        self.key_path = key_path or STORAGE_ROOT / "server" / "signing_key.raw"

    def _private_key(self) -> Ed25519PrivateKey:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            raw = self.key_path.read_bytes()
        except FileNotFoundError:
            generated = Ed25519PrivateKey.generate()
            raw = generated.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            try:
                with self.key_path.open("xb") as key_file:
                    key_file.write(raw)
            except FileExistsError:
                raw = self.key_path.read_bytes()
        return Ed25519PrivateKey.from_private_bytes(raw)

    def public_key_bytes(self) -> bytes:
        return self._private_key().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def key_id(self) -> str:
        return "ed25519-" + sha256_hex(self.public_key_bytes())[:16]

    def sign(self, manifest_bytes: bytes) -> bytes:
        return self._private_key().sign(manifest_bytes)
