"""Swagger routes for publishing and serving mock packages."""

import base64
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ManifestRead, PackageRead, ProductCreate, ProductRead
from app.db.session import get_session
from app.domain.rules import AccessDeniedError, RegistryRole
from app.services.packages import (
    InvalidPackage,
    PackageRegistryService,
    RegistryConflict,
    RegistryNotFound,
    UpdateServerService,
)

router = APIRouter(tags=["Packages"])
MAX_PACKAGE_BYTES = 16 * 1024 * 1024


def get_role(
    x_registry_role: Annotated[
        str,
        Header(description="Учебная роль: publisher или device; не подтверждает личность"),
    ] = "device",
) -> RegistryRole:
    try:
        return RegistryRole(x_registry_role.lower())
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Unknown registry role") from exc


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, AccessDeniedError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, RegistryNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, RegistryConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, InvalidPackage):
        return HTTPException(status_code=422, detail=str(exc))
    raise exc


@router.post("/products", response_model=ProductRead, status_code=201)
async def create_product(
    payload: ProductCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        return await PackageRegistryService(session).create_product(payload.name, payload.target, role)
    except (AccessDeniedError, RegistryConflict, InvalidPackage) as exc:
        raise _http_error(exc) from exc


@router.post("/products/{product_id}/packages", response_model=PackageRead, status_code=201)
async def publish_package(
    product_id: UUID,
    version: Annotated[str, Form(min_length=1, max_length=100)],
    file: Annotated[UploadFile, File()],
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        content = await file.read(MAX_PACKAGE_BYTES + 1)
        if len(content) > MAX_PACKAGE_BYTES:
            raise HTTPException(status_code=413, detail="Package exceeds 16 MiB limit")
        return await PackageRegistryService(session).publish_package(
            product_id, version, file.filename or "", content, role
        )
    except (AccessDeniedError, RegistryNotFound, RegistryConflict, InvalidPackage) as exc:
        raise _http_error(exc) from exc
    finally:
        await file.close()


@router.get("/products/{product_id}/packages", response_model=list[PackageRead])
async def list_packages(
    product_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        return await UpdateServerService(session).list_packages(product_id, role)
    except (AccessDeniedError, RegistryNotFound) as exc:
        raise _http_error(exc) from exc


@router.get("/products/{product_id}/latest", response_model=PackageRead)
async def latest_package(
    product_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        return await UpdateServerService(session).latest(product_id, role)
    except (AccessDeniedError, RegistryNotFound) as exc:
        raise _http_error(exc) from exc


@router.get("/packages/{package_id}/manifest", response_model=ManifestRead)
async def get_manifest(
    package_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        package = await UpdateServerService(session).manifest(package_id, role)
    except (AccessDeniedError, RegistryNotFound) as exc:
        raise _http_error(exc) from exc
    return ManifestRead(
        manifest=json.loads(package.manifest_bytes),
        signature_base64=base64.b64encode(package.signature).decode("ascii"),
        signing_key_id=package.signing_key_id,
    )


@router.get(
    "/packages/{package_id}/content",
    response_class=Response,
    responses={
        200: {
            "content": {
                "application/octet-stream": {
                    "schema": {"type": "string", "format": "binary"}
                }
            }
        }
    },
)
async def download_package(
    package_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    role: Annotated[RegistryRole, Depends(get_role)],
):
    try:
        _, content = await UpdateServerService(session).download(package_id, role)
    except (AccessDeniedError, RegistryNotFound) as exc:
        raise _http_error(exc) from exc
    return Response(content=content, media_type="application/octet-stream")
