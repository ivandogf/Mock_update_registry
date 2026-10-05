"""Install a VERIFIED local bundle. The manager owns the database transaction."""

import json
from datetime import datetime, timezone

from packaging.version import Version
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceState, DeviceTrustedPackage, Package, UpdateSession
from app.domain.rules import AccessDeniedError, StorageActor
from app.infrastructure.crypto import sha256_hex
from app.infrastructure.files import DeviceFileStore
from app.services.monitor import MonitorService
from app.services.temporary_storage import TemporaryStorageService


class InstallationError(Exception):
    pass


class InstallerService:
    def __init__(
        self, session: AsyncSession, storage: TemporaryStorageService | None = None,
        files: DeviceFileStore | None = None,
    ) -> None:
        self.session = session
        self.storage = storage or TemporaryStorageService(session)
        self.files = files or DeviceFileStore()
        self.monitor = MonitorService(session)

    async def install(self, update: UpdateSession) -> None:
        if update.state != "INSTALLING" or update.verification_result != "PASSED":
            message = "Installer requires an INSTALLING session with PASSED verification"
            await self.monitor.access_denied(
                update.id, actor="installer", operation="install", message=message,
                component="InstallerService",
            )
            raise AccessDeniedError(message)
        bundle = await self.storage.read(update.id, StorageActor.INSTALLER)
        device = await self.session.get(Device, update.device_id, populate_existing=True)
        state = await self.session.scalar(
            select(DeviceState).where(DeviceState.device_id == update.device_id)
            .with_for_update().execution_options(populate_existing=True)
        )
        package = await self.session.get(Package, update.target_package_id)
        if device is None or state is None or package is None:
            raise InstallationError("Device state or selected package is missing")
        if (state.current_package_id, state.fallback_package_id) != (
            update.original_current_package_id, update.original_fallback_package_id,
        ):
            raise InstallationError("Device pointers changed since update creation")
        # Detect filesystem changes between verification and copying. Registry release
        # metadata is immutable through the API and binds the local copy to its package ID.
        try:
            manifest = json.loads(bundle.manifest_bytes)
            digest = sha256_hex(bundle.content)
            if (
                package.product_id != device.product_id or package.target != device.target
                or manifest["package_id"] != str(package.id)
                or manifest["product_id"] != str(device.product_id)
                or manifest["target"] != device.target
                or Version(manifest["version"]) != Version(package.version)
                or digest != manifest["sha256_hex"] or digest != package.sha256_hex
                or len(bundle.content) != package.size_bytes
            ):
                raise ValueError("Verified bundle no longer matches the selected release")
        except (ValueError, KeyError, TypeError) as exc:
            raise InstallationError("Verified bundle integrity check failed") from exc

        key = self.files.save(device.id, update.id, bundle.content)
        if sha256_hex(self.files.read(key, device.id)) != digest:
            raise InstallationError("Installed local copy differs from verified bytes")
        # No trust record or device pointer is changed before copying has succeeded.
        trusted = await self.session.get(DeviceTrustedPackage, (device.id, package.id))
        if trusted is None:
            trusted = DeviceTrustedPackage(device_id=device.id, package_id=package.id)
            self.session.add(trusted)
        trusted.local_storage_key = key
        trusted.verified_sha256_hex = digest
        trusted.verified_at = datetime.now(timezone.utc)
        await self.session.flush()
        state.fallback_package_id = state.current_package_id
        state.current_package_id = package.id
        state.updated_at = datetime.now(timezone.utc)
        self.monitor.record(
            "DEVICE_CURRENT_UPDATED", "Installed package is now device current; previous current is fallback",
            component="InstallerService", session_id=update.id,
            details={"current_package_id": str(package.id),
                     "fallback_package_id": str(state.fallback_package_id) if state.fallback_package_id else None},
        )
        await self.session.flush()
