"""Explicit local trust setup: python -m app.provision_key [--public-key FILE]."""

import argparse
from pathlib import Path

from app.infrastructure.crypto import TrainingSigner
from app.infrastructure.trusted_keys import TrustedPublicKeyStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a trusted Ed25519 public key")
    parser.add_argument("--public-key", type=Path, help="Previously trusted raw 32-byte public key")
    args = parser.parse_args()
    # The operator explicitly trusts the local training signer, separately from verification.
    raw = args.public_key.read_bytes() if args.public_key else TrainingSigner().public_key_bytes()
    store = TrustedPublicKeyStore()
    key_id = store.provision(raw)
    print(f"Trusted public key: {key_id}")
    print(f"Public key file: {store.directory / (key_id + '.pub')}")


if __name__ == "__main__":
    main()
