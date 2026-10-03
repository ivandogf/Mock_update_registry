"""Download through Gateway and leave a sealed package for Verifier."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, DeviceState, TemporaryStorage, UpdateSession
from app.domain.rules import ACTIVE_UPDATE_STATES, StorageActor, require_update_transition
from app.services.gateway import ExternalNetworkGateway, GatewayError
from app.services.monitor import MonitorService
from app.services.packages import NoPublishedRelease, RegistryNotFound
from app.services.temporary_storage import TemporaryStorageError, TemporaryStorageService


class DownloadConflict(Exception):
    pass


class DownloaderService:
    CHUNK_BYTES = 1024 * 1024

    def __init__(
        self, session: AsyncSession, gateway: ExternalNetworkGateway,
        storage: TemporaryStorageService | None = None,
    ) -> None:
        self.session = session
        self.gateway = gateway
        self.storage = storage or TemporaryStorageService(session)
        self.monitor = MonitorService(session)

    def _transition(self, update: UpdateSession, state: str) -> None:
        require_update_transition(update.state, state)
        update.state = state

    def _event(self, session_id: UUID, event: str, message: str, level: str = "INFO") -> None:
        self.monitor.record(event, message, component="DownloaderService", level=level, session_id=session_id)

    async def download(self, device_id: UUID) -> UpdateSession:
        device = await self.session.get(Device, device_id, with_for_update=True)
        if device is None:
            raise RegistryNotFound("Device not found")
        active = await self.session.scalar(
            select(UpdateSession.id).where(
                UpdateSession.device_id == device_id, UpdateSession.state.in_(ACTIVE_UPDATE_STATES)
            ).limit(1)
        )
        if active is not None:
            raise DownloadConflict("Device already has an active update session")
        device_state = await self.session.get(DeviceState, device_id)
        current = device_state.current_package_id if device_state else None
        product_id = device.product_id
        session_id = uuid4()
        update = UpdateSession(
            id=session_id, device_id=device_id, state="IDLE",
            original_current_package_id=current,
            original_fallback_package_id=device_state.fallback_package_id if device_state else None,
            started_at=datetime.now(timezone.utc),
        )
        self.session.add(update)
        await self.session.flush()
        self._transition(update, "CHECKING")
        self._event(session_id, "UPDATE_CHECK_STARTED", "Checking the update server")
        await self.session.commit()
        try:
            try:
                latest = await self.gateway.latest(product_id)
            except NoPublishedRelease:
                latest = None
            if latest is None or latest.id == current:
                self._transition(update, "NO_UPDATE")
                update.finished_at = datetime.now(timezone.utc)
                self._event(session_id, "NO_UPDATE", "No new published package is available")
                await self.session.commit()
                return update
            target_id = latest.id
            manifest = await self.gateway.manifest(target_id)
            if manifest.id != target_id or manifest.product_id != product_id:
                raise TemporaryStorageError("Server returned a package for another product")
            update.target_package_id = target_id
            self._event(session_id, "UPDATE_FOUND", "A package is available for download")
            self._transition(update, "DOWNLOADING")
            self._event(session_id, "DOWNLOAD_STARTED", "Downloading to temporary storage")
            await self.storage.create(
                session_id, manifest.manifest_bytes, manifest.signature,
                manifest.signing_key_id, StorageActor.DOWNLOADER,
            )
            await self.session.commit()
            source, content = await self.gateway.download(target_id)
            if source.id != target_id:
                raise TemporaryStorageError("Downloaded package does not match the selected package")
            for offset in range(0, len(content), self.CHUNK_BYTES):
                await self.storage.append(session_id, content[offset:offset + self.CHUNK_BYTES], StorageActor.DOWNLOADER)
                await self.session.commit()
            self._event(session_id, "DOWNLOAD_COMPLETED", "Download completed")
            await self.storage.seal(session_id, StorageActor.DOWNLOADER)
            self._transition(update, "VERIFYING")
            await self.session.commit()
            return update
        except (GatewayError, RegistryNotFound, TemporaryStorageError, OSError, ValueError) as exc:
            await self.session.rollback()
            update = await self.session.get(UpdateSession, session_id)
            row = await self.session.get(TemporaryStorage, session_id)
            if row is not None and row.state == "WRITE":
                await self.storage.cleanup(session_id, StorageActor.DOWNLOADER)
            self._transition(update, "FAILED")
            update.failure_code = type(exc).__name__
            update.finished_at = datetime.now(timezone.utc)
            self._event(session_id, "DOWNLOAD_FAILED", str(exc), "ERROR")
            await self.session.commit()
            return update
        except BaseException:
            await self.session.rollback()
            # Do not leave an uncommitted package usable after a database failure.
            self.storage.files.delete(f"temporary/{session_id.hex}.pkg")
            raise
