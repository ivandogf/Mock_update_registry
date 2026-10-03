"""Download staging, session status and audit events."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.packages import get_role
from app.api.schemas import AuditEventRead, TemporaryStorageRead, UpdateSessionRead
from app.db.models import TemporaryStorage, UpdateSession
from app.db.session import get_session
from app.domain.rules import RegistryAction, RegistryRole, require_access
from app.services.downloader import DownloadConflict, DownloaderService
from app.services.gateway import ExternalNetworkGateway
from app.services.monitor import MonitorService
from app.services.packages import RegistryNotFound, UpdateServerService

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
    require_access(role, RegistryAction.READ_RELEASE)
    gateway = ExternalNetworkGateway(UpdateServerService(session))
    try:
        update = await DownloaderService(session, gateway).download(device_id)
    except RegistryNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DownloadConflict as exc:
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
