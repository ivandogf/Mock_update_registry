"""Coordinate transactions and state transitions; services perform individual operations."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditEvent, Device, DeviceState, TemporaryStorage, UpdateSession
from app.domain.rules import (
    ACTIVE_UPDATE_STATES, AccessDeniedError, require_installation_ready, require_update_transition,
)
from app.services.downloader import DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.installer import InstallerService
from app.services.monitor import MonitorService
from app.services.packages import RegistryNotFound, UpdateServerService
from app.services.rollback import RollbackError, RollbackService
from app.services.verifier import VerifierService


class UpdateConflict(Exception):
    pass


class UpdateManagerService:
    def __init__(
        self, session: AsyncSession, installer: InstallerService | None = None,
        rollback: RollbackService | None = None,
        downloader: DownloaderService | None = None, verifier: VerifierService | None = None,
    ) -> None:
        self.session = session
        self.installer = installer or InstallerService(session)
        self.rollback_service = rollback or RollbackService(session, self.installer.files)
        self.downloader = downloader
        self.verifier = verifier
        self.monitor = MonitorService(session)

    def _transition(self, update: UpdateSession, state: str) -> None:
        require_update_transition(update.state, state)
        update.state = state

    def _event(self, update: UpdateSession, event: str, message: str, **details) -> None:
        self.monitor.record(
            event, message, component="UpdateManagerService", session_id=update.id,
            level="ERROR" if event.endswith("FAILED") else "INFO", details=details,
        )

    async def _locked(self, session_id: UUID, *, lock_storage: bool = False):
        update = await self.session.get(UpdateSession, session_id, populate_existing=True)
        if update is None:
            raise RegistryNotFound("Update session not found")
        # Serialize device operations. Lock storage before the session to share the
        # Verifier's order. NO KEY UPDATE allows the independent ACCESS_DENIED audit FK.
        device = await self.session.get(Device, update.device_id, with_for_update=True, populate_existing=True)
        if device is None:
            raise RegistryNotFound("Device not found")
        storage = None
        if lock_storage:
            storage = await self.session.scalar(
                select(TemporaryStorage).where(TemporaryStorage.session_id == session_id)
                .with_for_update().execution_options(populate_existing=True)
            )
        update = await self.session.scalar(
            select(UpdateSession).where(UpdateSession.id == session_id)
            .with_for_update(key_share=True).execution_options(populate_existing=True)
        )
        state = await self.session.scalar(
            select(DeviceState).where(DeviceState.device_id == device.id)
            .with_for_update().execution_options(populate_existing=True)
        )
        if state is None:
            raise UpdateConflict("Device state is missing")
        return update, storage, state

    async def _deny(self, update: UpdateSession, operation: str, message: str, storage_state=None) -> None:
        await self.monitor.access_denied(
            update.id, actor="manager", operation=operation, message=message,
            component="UpdateManagerService", storage_state=storage_state,
        )
        raise UpdateConflict(message)

    async def _rollback(self, update: UpdateSession, *, discard_failed_target: bool) -> None:
        self._transition(update, "ROLLING_BACK")
        self._event(update, "ROLLBACK_STARTED", "Restoring original device state from trusted local copies")
        await self.session.flush()
        try:
            async with self.session.begin_nested():
                await self.rollback_service.restore(update, discard_failed_target=discard_failed_target)
                await self.session.flush()
        except Exception as exc:
            await self.session.refresh(update)
            self._transition(update, "FAILED")
            update.failure_code = exc.code if isinstance(exc, RollbackError) else "ROLLBACK_FAILED"
            self._event(update, "ROLLBACK_FAILED", str(exc), failure_code=update.failure_code)
        else:
            self._transition(update, "ROLLED_BACK")
            self._event(
                update, "ROLLBACK_COMPLETED", "Original device current/fallback restored",
                current_package_id=str(update.original_current_package_id) if update.original_current_package_id else None,
                fallback_package_id=str(update.original_fallback_package_id) if update.original_fallback_package_id else None,
            )
        update.finished_at = datetime.now(timezone.utc)

    async def install(self, session_id: UUID) -> UpdateSession:
        try:
            update, storage, state = await self._locked(session_id, lock_storage=True)
            try:
                require_installation_ready(
                    update.state, update.verification_result,
                    storage.state if storage is not None and storage.cleaned_at is None else None,
                )
            except AccessDeniedError as exc:
                await self._deny(update, "install", str(exc), storage.state if storage else None)
            if (state.current_package_id, state.fallback_package_id) != (
                update.original_current_package_id, update.original_fallback_package_id,
            ):
                await self._deny(update, "install", "Device state changed since this update session was created")
            self._transition(update, "INSTALLING")
            self._event(update, "INSTALL_STARTED", "Installing verified package on the device")
            await self.session.flush()
            try:
                # A copy or DB failure cannot leave a trusted target or changed pointers.
                async with self.session.begin_nested():
                    await self.installer.install(update)
                    self._transition(update, "COMPLETED")
                    update.failure_code = None
                    update.finished_at = datetime.now(timezone.utc)
                    self._event(update, "INSTALL_COMPLETED", "Package installation completed")
                    await self.session.flush()
            except Exception as exc:
                await self.session.refresh(update)
                update.failure_code = "INSTALLATION_FAILED"
                self._event(update, "INSTALL_FAILED", str(exc), error_type=type(exc).__name__)
                await self._rollback(update, discard_failed_target=True)
            await self.session.commit()
            await self.installer.storage.cleanup_finished(session_id)
            await self.session.refresh(update)
            return update
        except Exception:
            await self.session.rollback()
            raise

    async def rollback(self, session_id: UUID) -> UpdateSession:
        try:
            update, _, state = await self._locked(session_id)
            retry = update.state == "FAILED" and (update.failure_code or "").startswith("ROLLBACK_")
            if update.state != "COMPLETED" and not retry:
                await self._deny(update, "rollback", "Rollback requires COMPLETED or a previous rollback failure")
            active = await self.session.scalar(
                select(UpdateSession.id).where(
                    UpdateSession.device_id == update.device_id, UpdateSession.id != update.id,
                    UpdateSession.state.in_(ACTIVE_UPDATE_STATES),
                ).limit(1)
            )
            failed_install = retry and await self.session.scalar(
                select(AuditEvent.id).where(
                    AuditEvent.session_id == update.id, AuditEvent.event_type == "INSTALL_FAILED",
                ).limit(1)
            ) is not None
            expected = (
                (update.original_current_package_id, update.original_fallback_package_id) if failed_install
                else (update.target_package_id, update.original_current_package_id)
            )
            if active is not None or (state.current_package_id, state.fallback_package_id) != expected:
                await self._deny(update, "rollback", "A different update changed or is using this device")
            if not retry:
                update.failure_code = None
            await self._rollback(update, discard_failed_target=bool(failed_install))
            if update.state == "ROLLED_BACK" and retry:
                update.failure_code = "INSTALLATION_FAILED" if failed_install else None
            await self.session.commit()
            await self.installer.storage.cleanup_finished(session_id)
            await self.session.refresh(update)
            return update
        except Exception:
            await self.session.rollback()
            raise

    async def run(self, device_id: UUID) -> UpdateSession:
        """Normal end-to-end path; failure injection is not part of this manager."""
        downloader = self.downloader or DownloaderService(
            self.session, ExternalNetworkGateway(UpdateServerService(self.session)), self.installer.storage,
        )
        update = await downloader.download(device_id)
        if update.state != "VERIFYING":
            return update
        verifier = self.verifier or VerifierService(self.session, self.installer.storage)
        update = await verifier.verify(update.id)
        if update.verification_result != "PASSED":
            return update
        return await self.install(update.id)
