"""Verify sealed bytes using independently provisioned public keys; never install."""

import json
import re
from datetime import datetime, timezone
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceState, Package, UpdateSession
from app.domain.rules import StorageActor, require_update_transition
from app.infrastructure.crypto import sha256_hex
from app.infrastructure.files import BundleReadError, TemporaryBundle
from app.infrastructure.trusted_keys import TrustedPublicKeyStore, UntrustedSigningKey
from app.services.monitor import MonitorService
from app.services.packages import RegistryNotFound
from app.services.temporary_storage import StorageIntegrityError, TemporaryStorageService


class VerificationConflict(Exception):
    pass


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate manifest field")
        result[name] = value
    return result


class VerifierService:
    def __init__(
        self, session: AsyncSession, storage: TemporaryStorageService | None = None,
        trusted_keys: TrustedPublicKeyStore | None = None,
    ) -> None:
        self.session = session
        self.storage = storage or TemporaryStorageService(session)
        self.trusted_keys = trusted_keys or TrustedPublicKeyStore()
        self.monitor = MonitorService(session)

    def _event(self, session_id: UUID, event: str, message: str) -> None:
        self.monitor.record(
            event, message, component="VerifierService", session_id=session_id,
            level="WARNING" if event.endswith("INVALID") else "INFO",
        )

    async def _checks(self, update: UpdateSession, bundle: TemporaryBundle) -> tuple[str, str]:
        try:
            manifest = json.loads(bundle.manifest_bytes, object_pairs_hook=_unique_object)
            if not isinstance(manifest, dict):
                raise ValueError("Manifest must be an object")
            expected_hash = manifest.get("sha256_hex")
            if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise ValueError("Manifest must contain a SHA-256 digest")
            if sha256_hex(bundle.content) != expected_hash:
                raise ValueError("Downloaded bytes do not match the manifest SHA-256")
        except (ValueError, TypeError) as exc:
            return "HASH_INVALID", str(exc)
        self._event(update.id, "HASH_VALID", "Downloaded bytes match the manifest SHA-256")

        try:
            if manifest.get("signature_algorithm") != "ed25519":
                raise ValueError("Manifest signature algorithm must be Ed25519")
            if manifest.get("signing_key_id") != bundle.signing_key_id:
                raise ValueError("Manifest and envelope signing key IDs differ")
            public_key = self.trusted_keys.get(bundle.signing_key_id)
            public_key.verify(bundle.signature, bundle.manifest_bytes)
        except (InvalidSignature, UntrustedSigningKey, ValueError, TypeError) as exc:
            return "SIGNATURE_INVALID", str(exc) or "Manifest signature is invalid"
        self._event(update.id, "SIGNATURE_VALID", "Manifest signature matches a pre-trusted public key")

        device = await self.session.get(Device, update.device_id, populate_existing=True)
        try:
            if device is None or manifest.get("target") != device.target:
                raise ValueError("Manifest target does not match the device")
            # Bind the signed manifest to the selected release and device product.
            if UUID(manifest["product_id"]) != device.product_id:
                raise ValueError("Manifest product does not match the device")
            if UUID(manifest["package_id"]) != update.target_package_id:
                raise ValueError("Manifest package does not match the update session")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            return "TARGET_INVALID", str(exc)
        self._event(update.id, "TARGET_VALID", "Signed package target and identity match the device/session")

        try:
            candidate = manifest.get("version")
            if not isinstance(candidate, str):
                raise ValueError("Manifest version must be a PEP 440 string")
            candidate_version = Version(candidate)
            state = await self.session.get(DeviceState, device.id, populate_existing=True)
            if state is None:
                raise ValueError("Device state is missing")
            if state.current_package_id is not None:
                current = await self.session.get(Package, state.current_package_id, populate_existing=True)
                if current is None:
                    raise ValueError("Current device package is missing")
                if candidate_version <= Version(current.version):
                    raise ValueError("Package version must be strictly newer than the device version")
            # A device without an installed package accepts its first valid version.
        except (InvalidVersion, ValueError, TypeError) as exc:
            return "VERSION_INVALID", str(exc)
        self._event(update.id, "VERSION_VALID", "Package version is valid and newer, or this is the first package")
        return "PASSED", "Package verification succeeded"

    async def verify(self, session_id: UUID) -> UpdateSession:
        try:
            update = await self.session.get(UpdateSession, session_id)
            if update is None:
                raise RegistryNotFound("Update session not found")
            read_error = None
            try:
                # Locks storage until commit and audits access to any non-SEALED state.
                bundle = await self.storage.read(session_id, StorageActor.VERIFIER)
            except (BundleReadError, StorageIntegrityError) as exc:
                read_error = str(exc)
            # Refresh after the storage lock: concurrent verification may have finished.
            update = await self.session.scalar(
                select(UpdateSession).where(UpdateSession.id == session_id)
                .execution_options(populate_existing=True)
            )
            if update.state != "VERIFYING":
                raise VerificationConflict("Update session must be in VERIFYING")
            result, message = (
                ("HASH_INVALID", read_error) if read_error is not None
                else await self._checks(update, bundle)
            )
            passed = result == "PASSED"
            if not passed:
                self._event(session_id, result, message)
                require_update_transition(update.state, "REJECTED")
                update.state = "REJECTED"
                update.finished_at = datetime.now(timezone.utc)
            update.verification_result = result
            update.failure_code = None if passed else result
            # Emits exactly one PACKAGE_VERIFIED/PACKAGE_REJECTED in this transaction.
            await self.storage.set_verification_result(session_id, passed, StorageActor.VERIFIER)
            await self.session.commit()
            return update
        except Exception:
            await self.session.rollback()
            raise
