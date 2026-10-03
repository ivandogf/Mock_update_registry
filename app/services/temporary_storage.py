"""State-controlled temporary storage. The caller commits each operation."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import TemporaryStorage, UpdateSession
from app.domain.enums import TemporaryStorageState
from app.domain.rules import (
    StorageActor, require_storage_access, require_storage_transition,
)
from app.infrastructure.files import TemporaryBundle, TemporaryFileStore
from app.services.monitor import MonitorService


class TemporaryStorageError(Exception):
    pass


class TemporaryStorageService:
    MAX_BYTES = 16 * 1024 * 1024

    def __init__(self, session: AsyncSession, files: TemporaryFileStore | None = None) -> None:
        self.session = session
        self.files = files or TemporaryFileStore()
        self.monitor = MonitorService(session)

    async def _locked(self, session_id: UUID) -> TemporaryStorage:
        result = await self.session.execute(
            select(TemporaryStorage).where(TemporaryStorage.session_id == session_id)
            .with_for_update().execution_options(populate_existing=True)
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise TemporaryStorageError("Temporary storage not found")
        if row.cleaned_at is not None:
            raise TemporaryStorageError("Temporary storage has been cleaned")
        return row

    def _event(self, session_id: UUID, event: str, message: str) -> None:
        self.monitor.record(event, message, component="TemporaryStorageService", session_id=session_id)

    async def create(
        self, session_id: UUID, manifest_bytes: bytes, signature: bytes,
        signing_key_id: str, actor: StorageActor,
    ) -> TemporaryStorage:
        require_storage_access(actor, "write", TemporaryStorageState.WRITE)
        update = await self.session.get(UpdateSession, session_id)
        if update is None or update.state != "DOWNLOADING":
            raise TemporaryStorageError("Storage can only be created for a downloading session")
        if await self.session.get(TemporaryStorage, session_id) is not None:
            raise TemporaryStorageError("Temporary storage already exists")
        key = self.files.create(session_id, bytes(manifest_bytes), bytes(signature), signing_key_id)
        row = TemporaryStorage(session_id=session_id, state="WRITE", storage_key=key, bytes_written=0)
        self.session.add(row)
        self._event(session_id, "STORAGE_CREATED", "Temporary storage opened for writing")
        try:
            await self.session.flush()
        except BaseException:
            self.files.delete(key)
            raise
        return row

    async def append(self, session_id: UUID, content: bytes, actor: StorageActor) -> TemporaryStorage:
        row = await self._locked(session_id)
        require_storage_access(actor, "write", row.state)
        if row.bytes_written + len(content) > self.MAX_BYTES:
            raise TemporaryStorageError("Temporary package exceeds 16 MiB")
        self.files.append(row.storage_key, content, row.bytes_written)
        row.bytes_written += len(content)
        await self.session.flush()
        return row

    async def seal(self, session_id: UUID, actor: StorageActor) -> TemporaryStorage:
        row = await self._locked(session_id)
        require_storage_access(actor, "seal", row.state)
        require_storage_transition(row.state, "SEALED")
        if row.bytes_written == 0 or self.files.size(row.storage_key) != row.bytes_written:
            raise TemporaryStorageError("Cannot seal empty or incomplete storage")
        row.state = "SEALED"
        row.sealed_at = datetime.now(timezone.utc)
        self._event(session_id, "STORAGE_SEALED", "Temporary storage sealed; writing is closed")
        await self.session.flush()
        return row

    async def read(self, session_id: UUID, actor: StorageActor) -> TemporaryBundle:
        row = await self._locked(session_id)
        require_storage_access(actor, "read", row.state)
        bundle = self.files.read(row.storage_key)
        if len(bundle.content) != row.bytes_written:
            raise TemporaryStorageError("Temporary file size differs from stored byte count")
        return bundle

    async def set_verification_result(
        self, session_id: UUID, verified: bool, actor: StorageActor,
    ) -> TemporaryStorage:
        row = await self._locked(session_id)
        require_storage_access(actor, "verify", row.state)
        target = "VERIFIED" if verified else "REJECTED"
        require_storage_transition(row.state, target)
        row.state = target
        row.verified_at = datetime.now(timezone.utc) if verified else None
        self._event(session_id, "PACKAGE_VERIFIED" if verified else "PACKAGE_REJECTED",
                    "Package verification succeeded" if verified else "Package verification rejected")
        await self.session.flush()
        return row

    async def cleanup(self, session_id: UUID, actor: StorageActor) -> None:
        result = await self.session.execute(
            select(TemporaryStorage).where(TemporaryStorage.session_id == session_id)
            .with_for_update().execution_options(populate_existing=True)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return
        require_storage_access(actor, "cleanup", row.state)
        if row.cleaned_at is not None:
            return
        self.files.delete(row.storage_key)
        row.cleaned_at = datetime.now(timezone.utc)
        self._event(session_id, "STORAGE_CLEANED", "Temporary files removed")
        await self.session.flush()
