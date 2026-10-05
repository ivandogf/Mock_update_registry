"""Pre-provisioned public keys. Package metadata cannot add keys to this store."""

import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import STORAGE_ROOT
from app.infrastructure.crypto import sha256_hex


class UntrustedSigningKey(ValueError):
    pass


class TrustedPublicKeyStore:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = (directory or STORAGE_ROOT / "trusted_keys").resolve()

    @staticmethod
    def key_id(raw: bytes) -> str:
        return "ed25519-" + sha256_hex(raw)[:16]

    def get(self, key_id: str) -> Ed25519PublicKey:
        if not isinstance(key_id, str) or not re.fullmatch(r"ed25519-[0-9a-f]{16}", key_id):
            raise UntrustedSigningKey("Invalid signing key ID")
        path = (self.directory / f"{key_id}.pub").resolve()
        if path.parent != self.directory:
            raise UntrustedSigningKey("Invalid trusted key path")
        try:
            raw = path.read_bytes()
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (OSError, ValueError) as exc:
            raise UntrustedSigningKey("Signing key is not in the trusted public key store") from exc
        if self.key_id(raw) != key_id:
            raise UntrustedSigningKey("Trusted public key does not match its ID")
        return key

    def provision(self, raw: bytes) -> str:
        """Operator setup only; never called by Downloader or Verifier."""
        Ed25519PublicKey.from_public_bytes(raw)
        key_id = self.key_id(raw)
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{key_id}.pub"
        try:
            with path.open("xb") as file:
                file.write(raw)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise UntrustedSigningKey("A different trusted key already uses this ID")
        return key_id
