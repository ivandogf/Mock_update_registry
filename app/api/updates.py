"""Update stages, full normal flow, rollback, session status and audit events."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.packages import get_role
from app.api.schemas import AuditEventRead, TemporaryStorageRead, UpdateSessionRead
from app.db.models import TemporaryStorage, UpdateSession
from app.db.session import get_session
from app.domain.rules import AccessDeniedError, RegistryAction, RegistryRole
from app.services.downloader import DownloadConflict, DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.monitor import MonitorService
from app.services.packages import RegistryNotFound, UpdateServerService
from app.services.temporary_storage import TemporaryStorageError
from app.services.verifier import VerificationConflict, VerifierService
from app.services.update_manager import UpdateConflict, UpdateManagerService

router = APIRouter(tags=["Updates"])


async def session_response(session: AsyncSession, update: UpdateSession) -> UpdateSessionRead:
    response = UpdateSessionRead.model_validate(update)
    storage = await session.get(TemporaryStorage, update.id)
    if storage is not None:
        response.temporary_storage = TemporaryStorageRead.model_validate(storage)
    return response


@router.post("/devices/{device_id}/updates/download", response_model=UpdateSessionRead, status_code=201)
async def download_update(
    device_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        await MonitorService(session).require_access(
            role, RegistryAction.READ_RELEASE, component="UpdatesAPI",
            details={"device_id": str(device_id)},
        )
    except AccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    gateway = ExternalNetworkGateway(UpdateServerService(session))
    try:
        update = await DownloaderService(session, gateway).download(device_id)
    except RegistryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DownloadConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return await session_response(session, update)


@router.post("/updates/{session_id}/verify", response_model=UpdateSessionRead)
async def verify_update(
    session_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    """Verify SEALED storage. Returns PASSED or a rejection without starting installation."""
    try:
        await MonitorService(session).require_access(
            role, RegistryAction.READ_RELEASE, component="UpdatesAPI",
            details={"session_id": str(session_id)},
        )
    except AccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        update = await VerifierService(session).verify(session_id)
    except RegistryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (AccessDeniedError, VerificationConflict, TemporaryStorageError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return await session_response(session, update)


async def authorize_update(session: AsyncSession, role: RegistryRole, **details) -> None:
    try:
        await MonitorService(session).require_access(
            role, RegistryAction.READ_RELEASE, component="UpdatesAPI", details=details,
        )
    except AccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/updates/{session_id}/install", response_model=UpdateSessionRead)
async def install_update(
    session_id: UUID, session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    """Install an already VERIFIED package; automatically roll back installation errors."""
    await authorize_update(session, role, session_id=str(session_id))
    try:
        update = await UpdateManagerService(session).install(session_id)
    except RegistryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UpdateConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return await session_response(session, update)


@router.post("/updates/{session_id}/rollback", response_model=UpdateSessionRead)
async def rollback_update(
    session_id: UUID, session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    """Restore the session's original pointers from trusted local copies, without server access."""
    await authorize_update(session, role, session_id=str(session_id))
    try:
        update = await UpdateManagerService(session).rollback(session_id)
    except RegistryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UpdateConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return await session_response(session, update)


@router.post("/devices/{device_id}/updates/run", response_model=UpdateSessionRead, status_code=201)
async def run_update(
    device_id: UUID, session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    """Download, verify and install a normal update. Each service keeps its own responsibility."""
    await authorize_update(session, role, device_id=str(device_id))
    try:
        update = await UpdateManagerService(session).run(device_id)
    except RegistryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (DownloadConflict, UpdateConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return await session_response(session, update)


@router.get("/updates/{session_id}", response_model=UpdateSessionRead)
async def get_update(session_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]):
    update = await session.get(UpdateSession, session_id)
    if update is None:
        raise HTTPException(status_code=404, detail="Update session not found")
    return await session_response(session, update)


@router.get("/updates/{session_id}/events", response_model=list[AuditEventRead])
async def update_events(
    session_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]
):
    if await session.get(UpdateSession, session_id) is None:
        raise HTTPException(status_code=404, detail="Update session not found")
    return await MonitorService(session).events_for_session(session_id)
