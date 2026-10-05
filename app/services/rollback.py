"""Restore original device pointers using only trusted local copies."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceState, DeviceTrustedPackage, Package, UpdateSession
from app.infrastructure.crypto import sha256_hex
from app.infrastructure.files import DeviceFileStore


class RollbackError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RollbackService:
    def __init__(self, session: AsyncSession, files: DeviceFileStore | None = None) -> None:
        self.session = session
        self.files = files or DeviceFileStore()

    async def restore(self, update: UpdateSession, *, discard_failed_target: bool = False) -> None:
        """Caller owns transitions, audit and commit. Validate both pointers before changing either."""
        if update.state != "ROLLING_BACK":
            raise RollbackError("ROLLBACK_INVALID_STATE", "Rollback requires a ROLLING_BACK session")
        if discard_failed_target:
            try:
                self.files.delete(self.files.storage_key(update.device_id, update.id), update.device_id)
            except (OSError, ValueError) as exc:
                raise RollbackError("ROLLBACK_CLEANUP_FAILED", "Failed installation copy could not be removed") from exc
        device = await self.session.get(Device, update.device_id, populate_existing=True)
        state = await self.session.scalar(
            select(DeviceState).where(DeviceState.device_id == update.device_id)
            .with_for_update().execution_options(populate_existing=True)
        )
        if device is None or state is None:
            raise RollbackError("ROLLBACK_DEVICE_STATE_MISSING", "Device state is missing")
        originals = (update.original_current_package_id, update.original_fallback_package_id)
        for package_id in set(originals) - {None}:
            trusted = await self.session.get(DeviceTrustedPackage, (device.id, package_id), populate_existing=True)
            if trusted is None:
                raise RollbackError("ROLLBACK_PACKAGE_NOT_TRUSTED", f"No trusted local copy for {package_id}")
            package = await self.session.get(Package, package_id)
            if package is None or package.product_id != device.product_id or package.target != device.target:
                raise RollbackError("ROLLBACK_PACKAGE_MISMATCH", "Original package does not belong to this device product/target")
            try:
                content = self.files.read(trusted.local_storage_key, device.id)
            except (OSError, ValueError) as exc:
                raise RollbackError("ROLLBACK_LOCAL_COPY_UNAVAILABLE", f"Trusted local copy is unavailable: {package_id}") from exc
            if sha256_hex(content) != trusted.verified_sha256_hex:
                raise RollbackError("ROLLBACK_HASH_MISMATCH", f"Trusted local copy has been corrupted: {package_id}")
        # With no originals, restore the initially empty device, without downloading anything.
        state.current_package_id, state.fallback_package_id = originals
        state.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        if discard_failed_target and update.target_package_id not in originals:
            trusted = await self.session.get(DeviceTrustedPackage, (device.id, update.target_package_id))
            # Preserve any copy trusted by an earlier successful installation of this release.
            if trusted is not None and trusted.local_storage_key == self.files.storage_key(device.id, update.id):
                await self.session.delete(trusted)
                await self.session.flush()
